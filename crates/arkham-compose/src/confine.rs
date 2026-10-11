//! `arkham init` plus the stack commands (`up`, `down`, `logs`):
//! generate-once-then-edit, then drive the compose project and enter the agent.

use std::collections::{BTreeMap, hash_map::DefaultHasher};
use std::ffi::OsString;
use std::fs;
use std::hash::{Hash as _, Hasher as _};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use tokio::process::Command;

use crate::error::Error;
use crate::expose::prune_workspace;
use crate::paths::{expand, translate};
use crate::stack::{STACK_SHAPE, current_uid, generate_stack, stack_shape_in};
use crate::workspace::Workspace;
use arkham_config::cli::{Cli, CliCommand, ProxyBackend};
use arkham_config::config::{AppConfig, RuleCfg, WorkspaceBuild, config_dir, project_config_write_path};
use arkham_pki::ca::load_or_generate;
use clap::Args;
use dirs::home_dir;
use libc::{SIG_DFL, SIGINT, c_int, sighandler_t, signal};
use toml_edit::{DocumentMut, Formatted, Item, Value};

/// The entrypoint the generated agent service runs: it makes arkham's CA trusted
/// inside the container before handing off, by installing it into the system
/// store every tool already reads, then chains to the image's own init —
/// `ARKHAM_INIT` when set, the common entrypoint script names otherwise, and
/// the command directly as the safe default. `arkham init` writes it when
/// absent, so an edited copy survives regeneration.
pub(crate) const ENTRYPOINT_SCRIPT: &str = r#"#!/bin/sh
set -e
# The compose file mounts arkham's certificate at the system CA location, so
# refreshing the store is the whole job. That needs root: run the agent service
# as root, or grant it passwordless sudo (devcontainer images usually do).
if [ "$(id -u)" = "0" ]; then
  update-ca-certificates >/dev/null 2>&1 || true
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  sudo -n update-ca-certificates >/dev/null 2>&1 || true
else
  echo "arkham: run the agent as root or bake the certificate into the image" >&2
  echo "arkham: https://github.com/casualjim/arkham/blob/main/docs/user/how-to/trust-the-ca.md" >&2
fi
# Publish this container's podman subnets for arkham's eBPF bypass list.
# Podman networks are created here long after arkham starts, so the loader
# cannot know them up front: this loop rewrites the shared bypass file from
# `podman network inspect` and arkham reloads it live. Only when the stack
# wires the file (ARKHAM_EBPF_BYPASS_FILE); without podman the subshell exits
# quietly, and a failing podman keeps the previous file. The temp-file plus
# rename means arkham never reads a half-written list.
if [ -n "${ARKHAM_EBPF_BYPASS_FILE:-}" ]; then
  (
    set +e
    while true; do
      if names=$(podman network ls --format '{{.Name}}' 2>/dev/null); then
        if [ -z "$names" ]; then
          : > "${ARKHAM_EBPF_BYPASS_FILE}.tmp" && mv "${ARKHAM_EBPF_BYPASS_FILE}.tmp" "$ARKHAM_EBPF_BYPASS_FILE"
        elif out=$(printf '%s\n' "$names" | xargs -r podman network inspect --format '{{range .Subnets}}{{.Subnet}}{{"\n"}}{{end}}' 2>/dev/null); then
          printf '%s\n' "$out" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' | sort -u > "${ARKHAM_EBPF_BYPASS_FILE}.tmp" \
            && mv "${ARKHAM_EBPF_BYPASS_FILE}.tmp" "$ARKHAM_EBPF_BYPASS_FILE"
        fi
      fi
      sleep 10
    done
  ) >/dev/null 2>&1 &
fi
# Hand over to the image's own init when there is one, so the container's real
# startup (service supervisors, sockets, whatever the image ships) still runs:
# ARKHAM_INIT names it for images without a common name, the usual entrypoint
# script names are tried next, and with none of them the command runs directly.
if [ -n "${ARKHAM_INIT:-}" ] && [ -x "$ARKHAM_INIT" ]; then
  exec "$ARKHAM_INIT" "$@"
fi
for init in /usr/local/bin/docker-entrypoint.sh /docker-entrypoint.sh /usr/local/bin/entrypoint.sh /entrypoint.sh; do
  if [ -x "$init" ]; then
    exec "$init" "$@"
  fi
done
exec "$@"
"#;

/// Create the host files the generated stack mounts, when they are missing: the
/// CA at `<dir>/ca.pem` (`ca.crt` and `ca.key` come with it, and the stack
/// mounts `ca.pem` for arkham and `ca.crt` for the agent) and the agent
/// entrypoint. The CA is never overwritten, so one you installed elsewhere
/// survives; the entrypoint is regenerated whenever it differs from the
/// generated script, so stale or hand-edited copies cannot linger. The
/// directory is the arkham config directory, which is what the compose defaults
/// point at, not `[proxy] ca_file`: that describes a host-run arkham, not the
/// container's mount. The storage directory is this workspace's, under the
/// state directory.
pub(crate) fn ensure_support_files(dir: &Path, storage: &Path) -> Result<Vec<(PathBuf, bool)>, Error> {
  let ca = dir.join("ca.pem");
  let entrypoint = dir.join("agent-entrypoint.sh");
  let mut files = Vec::new();
  let created = !ca.exists();
  match load_or_generate(&ca) {
    Ok(_) => files.push((ca, created)),
    // A read-only or unwritable config directory only warns: the stack still
    // starts when a compose layer mounts a CA made with `arkham ca`.
    Err(err) => tracing::warn!(path = %ca.display(), %err, "could not prepare the CA"),
  }
  files.push((entrypoint.clone(), write_entrypoint(&entrypoint)?));
  // The agent's inner container storage — see the generated compose file for
  // why this directory has to exist before the stack starts.
  let storage_created = !storage.exists();
  match fs::create_dir_all(storage) {
    Ok(()) => files.push((storage.to_path_buf(), storage_created)),
    Err(err) => tracing::warn!(path = %storage.display(), %err, "could not prepare the agent storage directory"),
  }
  Ok(files)
}

/// Write the agent entrypoint, replacing a stale or edited copy so the two
/// never drift: the file is generated output, and a compose layer overriding
/// `entrypoint:` is the way to run a custom script instead. Executable: docker
/// runs it directly.
pub(crate) fn write_entrypoint(path: &Path) -> Result<bool, Error> {
  if let Ok(existing) = fs::read_to_string(path)
    && existing == ENTRYPOINT_SCRIPT
  {
    return Ok(false);
  }
  let regenerated = path.exists();
  fs::write(path, ENTRYPOINT_SCRIPT).map_err(|source| Error::WriteFile {
    path: path.to_path_buf(),
    source,
  })?;
  fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|source| Error::ChmodFile {
    path: path.to_path_buf(),
    source,
  })?;
  if regenerated {
    println!("regenerated {} (replaced a stale or edited copy)", path.display());
  }
  Ok(!regenerated)
}

/// Resolve the config directory and this workspace's state directory, then
/// create what the stack mounts from them.
pub(crate) fn prepare_support_files(root: &Path) -> Result<Vec<(PathBuf, bool)>, Error> {
  let dir = config_dir().ok_or_else(|| Error::ConfigDir {
    detail: "unable to resolve the arkham config directory".to_string(),
  })?;
  ensure_support_files(&dir, &Workspace::new(root).state_dir().join("containers"))
}

/// Report the files the call actually created; absent ones are already there.
pub(crate) fn report_created(files: &[(PathBuf, bool)]) {
  for (path, created) in files {
    if *created {
      println!("wrote {}", path.display());
    }
  }
}

/// Skeleton content of a fresh bypass file: comments only, so arkham starts
/// with no runtime entries and the agent entrypoint's first rewrite replaces
/// the whole file atomically.
const BYPASS_FILE_SKELETON: &str = "# Arkham eBPF bypass CIDRs, one per line.\n# The agent entrypoint rewrites this file from `podman network inspect`;\n# arkham reloads it live. Blank lines and `#` comments are ignored.\n";

/// Create the runtime bypass file when missing; never overwrite it, since
/// the agent rewrites it at runtime. Returns whether it was created, so
/// callers can report it like the other support files.
async fn ensure_bypass_file(path: &Path) -> Result<bool, Error> {
  if path.exists() {
    return Ok(false);
  }
  tokio::fs::write(path, BYPASS_FILE_SKELETON)
    .await
    .map_err(|source| Error::WriteFile {
      path: path.to_path_buf(),
      source,
    })?;
  Ok(true)
}

/// The capture backend the generated stack runs: `--backend` when given,
/// `ebpf` otherwise. Linux only — the generated serve command and the host
/// wiring that goes with it exist for Linux capture backends, so any other
/// host is refused here rather than producing a stack that cannot capture.
pub(crate) fn resolve_backend(backend: Option<ProxyBackend>) -> Result<ProxyBackend, Error> {
  if !cfg!(target_os = "linux") {
    return Err(Error::LinuxOnly);
  }
  match backend {
    None => Ok(ProxyBackend::Ebpf),
    Some(ProxyBackend::None) => Err(Error::BackendNone),
    Some(backend) => Ok(backend),
  }
}

/// Write `content` unless the file is already there; `true` means it was
/// written now. Nothing existing is ever overwritten — that file is the
/// user's.
pub(crate) fn write_if_absent(path: &Path, content: &str) -> Result<bool, Error> {
  if path.exists() {
    return Ok(false);
  }
  if let Some(parent) = path.parent() {
    fs::create_dir_all(parent).map_err(|source| Error::CreateDir {
      path: parent.to_path_buf(),
      source,
    })?;
  }
  fs::write(path, content).map_err(|source| Error::WriteFile {
    path: path.to_path_buf(),
    source,
  })?;
  Ok(true)
}

/// Write `mise.agent.toml` from `mise.local.toml` when the workspace uses
/// mise for local tasks and has no agent file yet: host-home path prefixes
/// become the container home so the agent's tasks find the same files.
/// Never overwrites; `true` means it was written now.
///
/// # Errors
///
/// Returns an error when the local file cannot be read, rewritten, or
/// written.
pub(crate) fn ensure_mise_agent(root: &Path, home: &str) -> Result<bool, Error> {
  if !root.join("mise.toml").is_file() || !root.join("mise.local.toml").is_file() || root.join("mise.agent.toml").exists() {
    return Ok(false);
  }
  let local = root.join("mise.local.toml");
  let content = fs::read_to_string(&local).map_err(|source| Error::ReadFile {
    path: local.clone(),
    source,
  })?;
  let rewritten = rewrite_mise_toml(&content, home_dir().as_deref(), home)?;
  write_if_absent(&root.join("mise.agent.toml"), &rewritten)
}

/// Copy `mise.local.toml` with host-home prefixes rewritten to the container
/// home, reusing [`translate`] semantics on path-looking string values.
/// URLs and non-paths stay intact.
///
/// # Errors
///
/// Returns an error when the content is not valid TOML.
pub(crate) fn rewrite_mise_toml(content: &str, host_home: Option<&Path>, home: &str) -> Result<String, Error> {
  let mut document: DocumentMut = content.parse().map_err(|source| Error::MiseParse { source })?;
  rewrite_mise_item(document.as_item_mut(), host_home, home);
  Ok(document.to_string())
}

/// Rewrite one TOML value tree in place: every string under a home prefix
/// moves to the container home.
fn rewrite_mise_item(item: &mut Item, host_home: Option<&Path>, home: &str) {
  match item {
    Item::Value(value) => rewrite_mise_value(value, host_home, home),
    Item::Table(table) => {
      for (_, item) in table.iter_mut() {
        rewrite_mise_item(item, host_home, home);
      }
    }
    Item::ArrayOfTables(tables) => {
      for table in tables.iter_mut() {
        for (_, item) in table.iter_mut() {
          rewrite_mise_item(item, host_home, home);
        }
      }
    }
    Item::None => {}
  }
}
/// Rewrite one TOML value: arrays recurse, strings under the host home move
/// to the container home, everything else stays.
fn rewrite_mise_value(value: &mut Value, host_home: Option<&Path>, home: &str) {
  match value {
    Value::String(text) => {
      let rewritten = rewrite_mise_string(text.value(), host_home, home);
      *text = Formatted::new(rewritten);
    }
    Value::Array(items) => {
      for item in items.iter_mut() {
        rewrite_mise_value(item, host_home, home);
      }
    }
    Value::InlineTable(table) => {
      for (_, value) in table.iter_mut() {
        rewrite_mise_value(value, host_home, home);
      }
    }
    _ => {}
  }
}

/// One mise string: URLs and non-paths stay intact; a value under the host
/// home (after `~` expansion) moves to the container home prefix.
fn rewrite_mise_string(value: &str, host_home: Option<&Path>, home: &str) -> String {
  if value.contains("://") {
    return value.to_string();
  }
  let expanded = if value == "~" || value.starts_with("~/") {
    match host_home {
      Some(host_home) => format!("{}{}", host_home.display(), &value[1..]),
      None => return value.to_string(),
    }
  } else {
    value.to_string()
  };
  match host_home.and_then(|host_home| Path::new(&expanded).strip_prefix(host_home).ok()) {
    Some(rest) => Path::new(home).join(rest).to_string_lossy().into_owned(),
    None => value.to_string(),
  }
}

/// A warning when nothing will substitute — no rule in play and nothing the
/// registry could turn into one — since then every credential the agent
/// holds stays a decoy; `None` when a rule or a derivable name is in effect.
pub(crate) fn rules_warning(rules: &BTreeMap<String, RuleCfg>, derivable: &[String]) -> Option<String> {
  if !rules.is_empty() || !derivable.is_empty() {
    return None;
  }
  Some(
    "warning: no [rules.*] in play and nothing derives from fnox through the registry, \
     so nothing will be substituted and every credential the agent holds stays a decoy; \
     `arkham rules` lists what fnox and the registry cover"
      .to_string(),
  )
}

/// Digest of both config layers' bytes — global and workspace — plus the
/// `rules.d` override trees both sides, so a stack generated from different
/// settings can be told apart from a current one: generation reads all of
/// them, so editing any must regenerate. `DefaultHasher`
/// is enough: this only ever compares digests written by the same binary.
pub(crate) fn config_digest(root: &Path) -> u64 {
  use std::hash::{Hash as _, Hasher as _};
  fn hash_file(path: &Path, hasher: &mut std::collections::hash_map::DefaultHasher) {
    match std::fs::read(path) {
      Ok(bytes) => bytes.hash(hasher),
      Err(_) => "absent".hash(hasher),
    }
    path.hash(hasher);
  }
  fn hash_rules_dir(dir: &Path, hasher: &mut std::collections::hash_map::DefaultHasher) {
    let mut files = std::fs::read_dir(dir)
      .ok()
      .map(|entries| {
        entries
          .flatten()
          .map(|entry| entry.path())
          .filter(|path| path.is_file())
          .collect::<Vec<_>>()
      })
      .unwrap_or_default();
    files.sort();
    if files.is_empty() {
      "absent".hash(hasher);
      dir.hash(hasher);
      return;
    }
    for path in files {
      hash_file(&path, hasher);
    }
  }
  let mut hasher = std::collections::hash_map::DefaultHasher::new();
  let global = arkham_config::config::config_dir().map(|dir| dir.join("config.toml"));
  let legacy = root.join(".config").join("arkham.toml");
  for path in global.into_iter().chain([project_config_write_path(root), legacy]) {
    hash_file(&path, &mut hasher);
  }
  if let Some(global_rules) = arkham_config::config::rules_dir() {
    hash_rules_dir(&global_rules, &mut hasher);
  }
  hash_rules_dir(&arkham_config::config::project_rules_dir(root), &mut hasher);
  hasher.finish()
}

/// Whether the stack on disk was generated from a different workspace config
/// — which matters because the decoys are derived from the rules: a stack made
/// before a rule existed hands the agent a decoy that can never be swapped —
/// or by an older stack shape, which matters because `arkham agent` bundles
/// generation and must not leave an old wiring behind. A stack with no digest
/// beside it predates the check and counts as stale.
pub(crate) fn stack_is_stale(state_ws: &Path, root: &Path) -> bool {
  let shape_stale = std::fs::read_to_string(state_ws.join("compose.yml")).is_ok_and(|body| stack_shape_in(&body) != Some(STACK_SHAPE));
  if shape_stale {
    return true;
  }
  match std::fs::read_to_string(state_ws.join("config.digest")) {
    Ok(stored) => stored.trim() != config_digest(root).to_string(),
    Err(_) => true,
  }
}

/// The capture backend the stack on disk was generated with, when it can be
/// read back — a regeneration must not silently switch how traffic is
/// captured just because this run did not name a backend.
pub(crate) fn generated_backend(compose: &str) -> Option<ProxyBackend> {
  [
    ("ebpf", ProxyBackend::Ebpf),
    ("tun", ProxyBackend::Tun),
    ("tproxy", ProxyBackend::Tproxy),
  ]
  .into_iter()
  .find_map(|(name, backend)| compose.contains(&format!("\"--proxy-backend\", \"{name}\"")).then_some(backend))
}

/// Generate the workspace stack when it is absent, and regenerate it when the
/// workspace config changed since it was generated; a stack whose config is
/// unchanged is left alone, so hand edits survive until then.
pub(crate) async fn init_workspace(
  workspace: &Workspace,
  backend: ProxyBackend,
  explicit_backend: bool,
  arkham_version: &str,
) -> Result<(), Error> {
  let state_ws = workspace.state_dir();
  let ws_compose = state_ws.join("compose.yml");
  tokio::fs::create_dir_all(&state_ws).await.map_err(|source| Error::CreateDir {
    path: state_ws.clone(),
    source,
  })?;
  // The runtime bypass file the ebpf stack mounts must exist before compose
  // starts: docker creates a directory at a missing file mount, which then
  // breaks both the agent writer and arkham's reader. Created once, never
  // overwritten — the agent owns its contents at runtime.
  if backend == ProxyBackend::Ebpf && ensure_bypass_file(&state_ws.join("ebpf-bypass")).await? {
    println!("wrote {}", state_ws.join("ebpf-bypass").display());
  }
  let config = workspace.config()?;
  let derivable = workspace.selection()?.derivable_envs();
  if let Some(warning) = rules_warning(&config.rules, &derivable) {
    println!("{warning}");
  }
  report_created(&prepare_support_files(workspace.root())?);
  if let Some(home) = config.workspace.home.as_deref()
    && ensure_mise_agent(workspace.root(), home)?
  {
    println!("wrote {}", workspace.root().join("mise.agent.toml").display());
  }
  let existing = tokio::fs::read_to_string(&ws_compose).await.ok();
  if existing.is_some() {
    if !stack_is_stale(&state_ws, workspace.root()) {
      println!("exists, left untouched: {}", ws_compose.display());
      return Ok(());
    }
    println!(
      "regenerating {}: the workspace config or the stack shape changed since it was generated, so hand edits to it are replaced",
      ws_compose.display()
    );
  }
  // An unnamed backend keeps whatever the stack on disk already runs.
  let backend = match (explicit_backend, existing.as_deref().and_then(generated_backend)) {
    (false, Some(existing)) => existing,
    _ => backend,
  };
  let stack = generate_stack(workspace.root(), backend, arkham_version)?;
  tokio::fs::write(&ws_compose, stack).await.map_err(|source| Error::WriteFile {
    path: ws_compose.clone(),
    source,
  })?;
  tokio::fs::write(state_ws.join("config.digest"), config_digest(workspace.root()).to_string())
    .await
    .map_err(|source| Error::WriteFile {
      path: state_ws.join("config.digest"),
      source,
    })?;
  println!("generated: {}", ws_compose.display());
  Ok(())
}

/// The compose files on disk, in layer order.
fn compose_layers(workspace: &Workspace) -> Vec<PathBuf> {
  [
    config_dir().map(|dir| dir.join("compose.yml")),
    Some(workspace.state_dir().join("compose.yml")),
    Some(workspace.file()),
  ]
  .into_iter()
  .flatten()
  .filter(|path| path.is_file())
  .collect()
}

/// A `docker compose` command over those layers.
pub(crate) fn compose_command(workspace: &Workspace) -> Result<Command, Error> {
  let layers = compose_layers(workspace);
  if layers.is_empty() {
    return Err(Error::NoComposeLayers {
      root: workspace.root().to_path_buf(),
    });
  }
  let mut command = Command::new("docker");
  command.arg("compose");
  for layer in layers {
    command.arg("-f").arg(layer);
  }
  Ok(command)
}

/// Run a compose command and fail on a non-zero exit; its output is the user's.
async fn compose_status(command: &mut Command) -> Result<(), Error> {
  let status = command.status().await.map_err(|source| Error::SpawnCompose { source })?;
  if !status.success() {
    return Err(Error::ComposeFailed {
      status: status.to_string(),
    });
  }
  Ok(())
}

/// The same, for a compose command the user is meant to interrupt — an exec
/// session, a `--follow` log read. compose reports that interrupt as 130, and
/// an interrupt is the user getting what they asked for, not a failure.
async fn compose_status_interruptible(command: &mut Command) -> Result<(), Error> {
  let status = command.status().await.map_err(|source| Error::SpawnCompose { source })?;
  if !(status.success() || status.code() == Some(130)) {
    return Err(Error::ComposeFailed {
      status: status.to_string(),
    });
  }
  Ok(())
}

/// The compose arguments `arkham up` maps to: `--build` only when the agent
/// image must be (re)built, so a plain `up` never compiles a Dockerfile.
pub(crate) fn up_argv(will_build: bool) -> Vec<OsString> {
  let mut argv: Vec<OsString> = vec!["up".into(), "-d".into()];
  if will_build {
    argv.push("--build".into());
  }
  argv
}

/// Digest of the agent build inputs — the dockerfile bytes plus the context
/// tree's relative paths, sizes, and mtimes — so an edited Dockerfile or a
/// changed context rebuilds on the next `up` without a flag. Hashing file
/// contents across the whole context would resend it on every check;
/// metadata notices a change and stays cheap to read.
pub(crate) fn build_digest(root: &Path, build: &WorkspaceBuild) -> u64 {
  fn hash_file(path: &Path, hasher: &mut DefaultHasher) {
    match fs::read(path) {
      Ok(bytes) => bytes.hash(hasher),
      Err(_) => "absent".hash(hasher),
    }
    path.hash(hasher);
  }
  fn hash_tree(dir: &Path, root: &Path, hasher: &mut DefaultHasher) {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
      .ok()
      .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
      .unwrap_or_default();
    entries.sort();
    for path in entries {
      if path.is_dir() {
        hash_tree(&path, root, hasher);
        continue;
      }
      path.strip_prefix(root).unwrap_or(&path).hash(hasher);
      match path.metadata() {
        Ok(meta) => {
          meta.len().hash(hasher);
          meta.modified().ok().hash(hasher);
        }
        Err(_) => "absent".hash(hasher),
      }
    }
  }
  let home = home_dir();
  let mut hasher = DefaultHasher::new();
  hash_file(&expand(&build.dockerfile, root, home.as_deref()), &mut hasher);
  hash_tree(
    &expand(&build.context, root, home.as_deref()),
    &expand(&build.context, root, home.as_deref()),
    &mut hasher,
  );
  hasher.finish()
}

/// State file holding the last successfully built inputs digest.
fn build_digest_file(root: &Path) -> PathBuf {
  Workspace::new(root).state_dir().join("build.digest")
}

/// Whether this `up` must (re)build the agent image: `--build` forces it,
/// otherwise a `[workspace.build]` whose inputs changed since the last
/// successful build. No build section means no build, and `--build` then is
/// a config error, not a silent no-op.
fn should_build(workspace: &Workspace, is_forced: bool) -> Result<bool, Error> {
  let Some(build) = workspace.config()?.workspace.build else {
    if is_forced {
      return Err(Error::BuildNotConfigured);
    }
    return Ok(false);
  };
  if is_forced {
    return Ok(true);
  }
  let stored = fs::read_to_string(build_digest_file(workspace.root())).unwrap_or_default();
  Ok(stored.trim() != build_digest(workspace.root(), &build).to_string())
}

/// Record a successful build's inputs digest, or drop a stale digest file
/// when no build section configures one.
fn record_build_digest(workspace: &Workspace, was_built: bool) -> Result<(), Error> {
  let path = build_digest_file(workspace.root());
  match workspace.config()?.workspace.build {
    Some(build) if was_built => fs::write(&path, build_digest(workspace.root(), &build).to_string()).map_err(|source| Error::WriteFile {
      path: path.clone(),
      source,
    }),
    Some(_) => Ok(()),
    None => {
      if path.exists() {
        fs::remove_file(&path).map_err(|source| Error::RemoveFile {
          path: path.clone(),
          source,
        })?;
      }
      Ok(())
    }
  }
}

/// Start the layered project, making sure what it mounts exists first.
pub(crate) async fn up_workspace(workspace: &Workspace, is_forced: bool) -> Result<(), Error> {
  report_created(&prepare_support_files(workspace.root())?);
  // The bypass file an ebpf stack mounts must exist before compose starts,
  // even when generation is skipped (a plain `up`): docker creates a
  // directory at a missing file mount, which then breaks both the agent
  // writer and arkham's reader. The generated backend decides, since `up`
  // takes no backend flag.
  let backend = tokio::fs::read_to_string(workspace.state_dir().join("compose.yml"))
    .await
    .ok()
    .and_then(|body| generated_backend(&body));
  if backend == Some(ProxyBackend::Ebpf) && ensure_bypass_file(&workspace.state_dir().join("ebpf-bypass")).await? {
    println!("wrote {}", workspace.state_dir().join("ebpf-bypass").display());
  }
  let will_build = should_build(workspace, is_forced)?;
  let mut command = compose_command(workspace)?;
  command.args(up_argv(will_build));
  compose_status(&mut command).await?;
  record_build_digest(workspace, will_build)
}

/// Stop the layered project.
async fn down_workspace(workspace: &Workspace) -> Result<(), Error> {
  let mut command = compose_command(workspace)?;
  command.arg("down");
  compose_status(&mut command).await
}

/// The compose arguments `arkham logs` maps to: its flags only when they were
/// asked for, the tail always (compose defaults it to everything), then the
/// named services — none means every service in the stack.
pub(crate) fn logs_argv(args: &LogsArgs) -> Vec<OsString> {
  let mut compose: Vec<OsString> = vec!["logs".into()];
  if args.follow {
    compose.push("--follow".into());
  }
  if args.no_log_prefix {
    compose.push("--no-log-prefix".into());
  }
  compose.push("--tail".into());
  compose.push(args.tail.clone().into());
  compose.extend(args.services.iter().map(Into::into));
  compose
}

/// Read the stack's logs.
async fn logs_workspace(workspace: &Workspace, args: &LogsArgs) -> Result<(), Error> {
  let mut command = compose_command(workspace)?;
  command.args(logs_argv(args));
  compose_status_interruptible(&mut command).await
}

/// Enter the agent environment at the translated workspace directory: the
/// configured shell, or `command` when the caller passed one.
async fn exec_agent(workspace: &Workspace, command: &[OsString]) -> Result<(), Error> {
  let config = workspace.config()?;
  let home = config.workspace.container_home().to_string();
  let workdir = translate(workspace.root(), home_dir().as_deref(), &home);
  warn_uncovered(workspace, &config);
  let uid = current_uid();
  let argv: Vec<OsString> = if command.is_empty() {
    vec![config.workspace.shell.clone().unwrap_or_else(|| "sh".to_string()).into()]
  } else {
    command.to_vec()
  };
  let mut compose = compose_command(workspace)?;
  compose
    .arg("exec")
    .arg("-i")
    .arg("--workdir")
    .arg(&workdir)
    .arg("--user")
    .arg(uid.to_string())
    .arg("agent")
    .args(argv);
  compose_status_interruptible(&mut compose).await
}

/// Print one sorted warning for fnox-declared names no rule, passthrough, or
/// provider wiring covers, every time the agent is entered. Never prints
/// values. A missing fnox setup means nothing to cover, so it stays silent.
fn warn_uncovered(workspace: &Workspace, config: &AppConfig) {
  let Ok(selection) = workspace.selection() else {
    return;
  };
  if let Some(warning) = selection.coverage_warning(&config.workspace.passthrough) {
    println!("{warning}");
  }
}
/// Arguments for the `up` command.
#[derive(Args, Debug, Clone)]
pub struct UpArgs {
  /// Workspace directory; defaults to the current directory.
  pub workspace: Option<PathBuf>,
  /// (Re)build the agent image even when its Dockerfile and context are
  /// unchanged; without it a build happens only when missing or stale.
  #[arg(long)]
  pub build: bool,
}

/// Arguments for the `down` command.
#[derive(Args, Debug, Clone)]
pub struct DownArgs {
  /// Workspace directory; defaults to the current directory.
  pub workspace: Option<PathBuf>,
}

/// Arguments for the `logs` command.
#[derive(Args, Debug, Clone)]
pub struct LogsArgs {
  /// Workspace directory; defaults to the current directory. A flag rather
  /// than a positional because the service names already take that slot.
  #[arg(long)]
  pub workspace: Option<PathBuf>,
  /// Keep the output open and follow new lines.
  #[arg(long, short = 'f')]
  pub follow: bool,
  /// Print bare log lines, without the service name in front of each one.
  #[arg(long)]
  pub no_log_prefix: bool,
  /// How many lines to show from the end of each service's log; `all` for
  /// everything.
  #[arg(long, default_value = "all")]
  pub tail: String,
  /// Services to read; every service in the stack when none are named.
  #[arg(value_name = "SERVICE")]
  pub services: Vec<String>,
}

/// Arguments for the `init` command.
#[derive(Args, Debug, Clone)]
pub struct InitArgs {
  /// Workspace directory; defaults to the current directory.
  pub workspace: Option<PathBuf>,
  /// Capture backend the generated stack runs. Linux only: the backend is
  /// chosen at generation time and defaults to `ebpf`.
  #[arg(long, value_enum)]
  pub backend: Option<ProxyBackend>,
}

/// Arguments for the `agent` command.
#[derive(Args, Debug, Clone)]
pub struct AgentArgs {
  /// Workspace directory; defaults to the current directory.
  pub workspace: Option<PathBuf>,
  /// Stop the workspace stack when the shell or command exits; without it the
  /// stack keeps running.
  #[arg(long)]
  pub rm: bool,
  /// (Re)build the agent image even when its Dockerfile and context are
  /// unchanged; without it a build happens only when missing or stale.
  #[arg(long)]
  pub build: bool,
  /// Command to run in the agent instead of the configured shell; the
  /// arguments after `--`.
  #[arg(last = true)]
  pub command: Vec<OsString>,
}

/// `arkham init [--backend <backend>] [workspace]`: write the support files, a
/// stub workspace config when the workspace has none (rules derive at serve
/// time, so the file holds overrides and `[workspace]` keys only), and the
/// workspace stack into `<state-dir>/arkham/ws/<slug>/compose.yml` — the one
/// editable file where generated services and secret mounts live. An existing
/// stack is regenerated only when the workspace config changed since it was
/// generated.
impl CliCommand for InitArgs {
  type Error = Error;
  /// Runs the init generation.
  ///
  /// # Errors
  ///
  /// Returns an error when the host is not Linux, when the workspace cannot be
  /// resolved or its stack generated, or when the registry cannot be loaded.
  async fn run(self, _cli: &Cli, arkham_version: &str) -> Result<(), Self::Error> {
    let workspace = Workspace::resolve(self.workspace.as_deref())?;
    init_workspace(&workspace, resolve_backend(self.backend)?, self.backend.is_some(), arkham_version).await
  }
}

/// `arkham agent [workspace] [-- <command>...]`: the whole workspace lifecycle
/// in one idempotent run — generate what is missing, start the stack, then
/// enter the agent with the configured shell or `<command>`. The stack keeps
/// running when that exits, unless `rm` stops it, so the next call starts at
/// the exec.
impl CliCommand for AgentArgs {
  type Error = Error;
  /// Runs the agent lifecycle.
  ///
  /// # Errors
  ///
  /// Returns an error when the workspace cannot be resolved, generated, or
  /// started, plus when the compose command fails. A failed `rm` teardown is
  /// reported too, because the stack the caller asked to stop is still up.
  async fn run(self, _cli: &Cli, arkham_version: &str) -> Result<(), Self::Error> {
    let workspace = Workspace::resolve(self.workspace.as_deref())?;
    init_workspace(&workspace, resolve_backend(None)?, false, arkham_version).await?;
    up_workspace(&workspace, self.build).await?;
    if !self.rm {
      return exec_agent(&workspace, &self.command).await;
    }
    let exec = {
      let _survive_interrupt = SurviveInterrupt::new();
      exec_agent(&workspace, &self.command).await
    };
    let down = down_workspace(&workspace).await;
    exec?;
    down
  }
}

/// Ignore the terminal's interrupt for as long as it lives, so arkham reaches
/// the `rm` teardown after the agent session ends instead of dying beside it.
///
/// A handler rather than `SIG_IGN`: ignored dispositions survive `exec`, and
/// the agent would then be uninterruptible as well.
struct SurviveInterrupt;

impl SurviveInterrupt {
  #[must_use]
  fn new() -> Self {
    // Safety: the handler only returns, so no work happens inside the signal.
    unsafe { signal(SIGINT, swallow_interrupt as *const () as sighandler_t) };
    Self
  }
}

impl Drop for SurviveInterrupt {
  fn drop(&mut self) {
    // Safety: restores the disposition every process starts with.
    unsafe { signal(SIGINT, SIG_DFL) };
  }
}

extern "C" fn swallow_interrupt(_: c_int) {}

/// `arkham up [workspace]`: start the layered compose project `arkham init`
/// generated, making sure what it mounts exists first.
impl CliCommand for UpArgs {
  type Error = Error;
  /// Starts the stack.
  ///
  /// # Errors
  ///
  /// Returns an error when the workspace cannot be resolved, when the support
  /// files cannot be written, or when the compose command fails.
  async fn run(self, _cli: &Cli, _arkham_version: &str) -> Result<(), Self::Error> {
    up_workspace(&Workspace::resolve(self.workspace.as_deref())?, self.build).await
  }
}

/// `arkham down [workspace]`: stop the layered compose project.
impl CliCommand for DownArgs {
  type Error = Error;
  /// Stops the stack.
  ///
  /// # Errors
  ///
  /// Returns an error when the workspace cannot be resolved or when the compose
  /// command fails.
  async fn run(self, _cli: &Cli, _arkham_version: &str) -> Result<(), Self::Error> {
    let workspace = Workspace::resolve(self.workspace.as_deref())?;
    down_workspace(&workspace).await?;
    // Stopped publishings free their host ports: dropping the claims here
    // keeps the registry from pinning ports no stack holds. A registry
    // failure only warns — the stack is already down.
    match prune_workspace(&workspace.slug()) {
      Ok(true) => println!("released expose claims for {}", workspace.root().display()),
      Ok(false) => {}
      Err(err) => tracing::warn!(%err, "could not release expose claims"),
    }
    Ok(())
  }
}

/// `arkham logs [workspace]`: read the stack's logs.
impl CliCommand for LogsArgs {
  type Error = Error;
  /// Reads the stack's logs.
  ///
  /// # Errors
  ///
  /// Returns an error when the workspace cannot be resolved or when the compose
  /// command fails.
  async fn run(self, _cli: &Cli, _arkham_version: &str) -> Result<(), Self::Error> {
    logs_workspace(&Workspace::resolve(self.workspace.as_deref())?, &self).await
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn up_argv_adds_build_only_when_asked() {
    assert_eq!(up_argv(false), vec![OsString::from("up"), OsString::from("-d")]);
    assert_eq!(
      up_argv(true),
      vec![OsString::from("up"), OsString::from("-d"), OsString::from("--build")]
    );
  }

  #[test]
  fn build_digest_follows_the_dockerfile_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let docker = dir.path().join("docker");
    std::fs::create_dir(&docker).unwrap();
    let dockerfile = docker.join("Dockerfile.agent");
    std::fs::write(&dockerfile, "FROM scratch\n").unwrap();
    let build = WorkspaceBuild {
      dockerfile: PathBuf::from("docker/Dockerfile.agent"),
      context: PathBuf::from("docker"),
    };
    let before = build_digest(dir.path(), &build);
    std::fs::write(&dockerfile, "FROM scratch\nRUN true\n").unwrap();
    assert_ne!(build_digest(dir.path(), &build), before, "edited dockerfile rebuilds");
    assert_eq!(
      build_digest(dir.path(), &build),
      build_digest(dir.path(), &build),
      "same tree is stable"
    );
  }
}
