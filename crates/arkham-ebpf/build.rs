//! Build glue: compile the eBPF programs for the `bpf` target and make the
//! resulting object part of this crate's build output.
//!
//! `aya-build` shells out to nightly with `-Z build-std`, because the BPF
//! target has no prebuilt `core`. It writes the object to `$OUT_DIR`, which is
//! where `include_bytes_aligned!` in `src/lib.rs` picks it up.

use aya_build::{Package, Toolchain};

fn main() -> Result<(), Box<dyn std::error::Error>> {
  // Emit `cfg(bpf_target_arch=...)` so `aya-ebpf-bindings` selects the right
  // architecture's bindings; without it the bindings crate fails to compile.
  aya_build::emit_bpf_target_arch_cfg()?;
  let toolchain = match pinned_nightly() {
    Some(name) => Toolchain::Custom(name),
    None => Toolchain::Nightly,
  };
  aya_build::build_ebpf(
    [Package {
      name: "arkham-ebpf-programs",
      root_dir: "crates/arkham-ebpf-programs",
      ..Package::default()
    }],
    toolchain,
  )?;
  Ok(())
}

/// The pinned nightly from `mise.lock` (e.g. `nightly-2026-09-18`), if any.
///
/// `aya-build` runs `rustup run <name>`; bare `nightly` names a different
/// toolchain than the dated pin mise installs (the one carrying `rust-src`),
/// so resolve the pin and hand aya-build its exact name.
fn pinned_nightly() -> Option<&'static str> {
  let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../mise.lock")).ok()?;
  let mut in_rust = false;
  for line in lock.lines() {
    let line = line.trim();
    if line.starts_with('[') {
      in_rust = line == "[[tools.rust]]";
    } else if in_rust
      && line.starts_with("version")
      && let Some(v) = line.split('"').nth(1)
      && v.starts_with("nightly")
    {
      return Some(Box::leak(v.to_owned().into_boxed_str()));
    }
  }
  None
}
