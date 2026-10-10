//! Tool profile mounts: the selected profile's tool configs mounted where the
//! tools read them by default.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use hodor_config::config::SHARED_PROFILE;
use hodor_config::config::{ToolCfg, profile_chain, valid_profile};

use crate::error::Error;
use crate::paths::Mount;

/// Container location each tool reads its config from by default, keyed by the
/// directory name under `profiles/<profile>/`. `{home}` expands to
/// `[workspace] home`. `[tools.<name>] config_dir` overrides an entry or adds
/// one the table does not carry.
pub(crate) const TOOL_CONFIG_DIRS: &[(&str, &str)] = &[
  ("amazon-q", "{home}/.aws/amazonq"),
  ("amazonq", "{home}/.aws/amazonq"),
  ("amp", "{home}/.config/amp"),
  ("auggie", "{home}/.augment"),
  ("augment", "{home}/.augment"),
  ("claude", "{home}/.claude"),
  ("claude-code", "{home}/.claude"),
  ("cline", "{home}/.cline"),
  ("codebuddy", "{home}/.codebuddy"),
  ("codebuff", "{home}/.config/manicode"),
  ("codex", "{home}/.codex"),
  ("codex-cli", "{home}/.codex"),
  ("continue", "{home}/.continue"),
  ("copilot", "{home}/.copilot"),
  ("crush", "{home}/.config/crush"),
  ("cursor", "{home}/.cursor"),
  ("deepagents", "{home}/.deepagents"),
  ("droid", "{home}/.factory"),
  ("dsh", "{home}/.dsh"),
  ("factory", "{home}/.factory"),
  ("forge", "{home}/.forge"),
  ("gemini", "{home}/.gemini"),
  ("gemini-cli", "{home}/.gemini"),
  ("gh", "{home}/.config/gh"),
  ("goose", "{home}/.config/goose"),
  ("gptme", "{home}/.config/gptme"),
  ("grok", "{home}/.grok"),
  ("grok-build", "{home}/.grok"),
  ("hermes", "{home}/.hermes"),
  ("iflow", "{home}/.iflow"),
  ("junie", "{home}/.junie"),
  ("junie-cli", "{home}/.junie"),
  ("kilo", "{home}/.config/kilo"),
  ("kimi", "{home}/.kimi"),
  ("kimi-code", "{home}/.kimi-code"),
  ("kiro", "{home}/.kiro"),
  ("kiro-cli", "{home}/.kiro"),
  ("mimo", "{home}/.mimo-code"),
  ("mimo-code", "{home}/.mimo-code"),
  ("muse", "{home}/.muse-code"),
  ("muse-code", "{home}/.muse-code"),
  ("omp", "{home}/.omp"),
  ("open-interpreter", "{home}/.config/open-interpreter"),
  ("openclaw", "{home}/.openclaw"),
  ("openhands", "{home}/.openhands"),
  ("openinterpreter", "{home}/.config/open-interpreter"),
  ("opencode", "{home}/.config/opencode"),
  ("pi", "{home}/.pi"),
  ("qoder", "{home}/.qoder"),
  ("qwen", "{home}/.qwen"),
  ("qwen-code", "{home}/.qwen"),
  ("roo", "{home}/.config/roo"),
  ("roo-code", "{home}/.config/roo"),
  ("tea", "{home}/.config/tea"),
  ("trae", "{home}/.trae"),
  ("vibe", "{home}/.vibe"),
  ("warp", "{home}/.config/warp-terminal"),
  ("workbuddy", "{home}/.codebuddy"),
];

/// Profile roots searched for tool configs: the workspace's own directory
/// first, the global one next.
pub(crate) struct ProfileRoots<'a> {
  /// `<root>/.config/hodor/profiles/`, when generation knows the workspace.
  pub(crate) project: Option<&'a Path>,
  /// `<config-dir>/hodor/profiles/`, when the global config resolves.
  pub(crate) global: Option<&'a Path>,
}

impl ProfileRoots<'_> {
  /// A profile-chain layer carrying `name`, project first: the directory to
  /// mount when the tool is already installed somewhere.
  fn chain_dir(&self, chain: &[String], name: &str) -> Option<PathBuf> {
    [self.project, self.global]
      .into_iter()
      .flatten()
      .flat_map(|layer| chain.iter().map(move |parent| layer.join(parent).join(name)))
      .find(|dir| dir.is_dir())
  }

  /// Where a configured tool's missing profile dir is made: the global
  /// profiles dir only. The workspace's project layer is read-only — hodor
  /// never creates anything inside the project root.
  fn create_base(&self, profile: &str) -> Option<PathBuf> {
    self.global.map(|global| global.join(profile))
  }
}

/// Mount the selected profile's tool configs at the locations the tools read
/// by default, so nothing has to point a tool at them. Explicitly configured
/// tools mount (their missing profile dir is created in the global profiles
/// dir, never the project); known tools mount only a directory the profile
/// chain already carries — nothing is mapped for a tool nobody installed,
/// and nothing is ever generated inside the project root.
pub(crate) fn profile_mounts(
  roots: &ProfileRoots,
  profile: &str,
  configured: &BTreeMap<String, ToolCfg>,
  home: &str,
) -> Result<Vec<Mount>, Error> {
  let chain = profile_chain(roots.project, roots.global, profile)?;
  if let Some(global) = roots.global {
    let dir = global.join(SHARED_PROFILE);
    fs::create_dir_all(&dir).map_err(|source| Error::CreateDir { path: dir.clone(), source })?;
  }
  // Explicit `[tools]` entries are opted in: their profile dir is made under
  // the global profiles dir when no layer carries it, so a first-run setup
  // persists — and the project root stays untouched.
  let mut mounts = Vec::new();
  for (name, tool) in configured {
    if !valid_profile(name) {
      return Err(Error::ToolNameInvalid { name: name.clone() });
    }
    let container = tool.config_dir.replace("{home}", home);
    if !container.starts_with('/') {
      return Err(Error::ToolConfigNotAbsolute {
        name: name.clone(),
        template: tool.config_dir.clone(),
      });
    }
    let host = match (roots.chain_dir(&chain, name), roots.create_base(profile)) {
      (Some(existing), _) => existing,
      (None, Some(base)) => {
        let dir = base.join(name);
        fs::create_dir_all(&dir).map_err(|source| Error::CreateDir { path: dir.clone(), source })?;
        dir
      }
      (None, None) => continue,
    };
    mounts.push(Mount {
      host,
      container: PathBuf::from(container),
      ro: false,
    });
  }
  // Known tools nobody configured mount only a directory the profile chain
  // already has: nothing is mapped for a tool nobody installed.
  for (name, template) in TOOL_CONFIG_DIRS {
    if configured.contains_key(*name) {
      continue;
    }
    let Some(host) = roots.chain_dir(&chain, name) else {
      continue;
    };
    mounts.push(Mount {
      host,
      container: PathBuf::from(template.replace("{home}", home)),
      ro: false,
    });
  }
  Ok(mounts)
}
