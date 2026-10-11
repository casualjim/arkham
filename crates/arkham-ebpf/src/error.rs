//! Typed errors for eBPF capture setup and serving.

use std::io::Error as IoError;
use std::path::PathBuf;

use aya::EbpfError;
use aya::maps::MapError;
use aya::programs::ProgramError;

/// Every way eBPF capture setup and serving can fail.
///
/// Every one of these is fatal for capture: a silent failure would leave
/// traffic flowing unproxied while the operator believes it is captured.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// A proxy-leg failure passes through.
  #[error(transparent)]
  Proxy(#[from] arkham_proxy::Error),
  /// A raw I/O failure with no extra context.
  #[error(transparent)]
  Io(#[from] IoError),
  /// `/proc/self/cgroup` cannot be read.
  #[error("read /proc/self/cgroup: {origin}")]
  ReadCgroupFile {
    /// Underlying I/O failure.
    #[source]
    origin: IoError,
  },
  /// This process is not in a cgroup v2 tree.
  #[error("no `0::<path>` line in /proc/self/cgroup: not a cgroup v2 process")]
  NotCgroupV2,
  /// The own cgroup is the cgroup root, which encloses nothing.
  #[error(
    "no cgroup encloses {path}: it is the cgroup root, where attaching would capture every process on the machine; \
     pass an explicit --ebpf-cgroup path",
    path = path.display()
  )]
  NoEnclosingCgroup {
    /// Own cgroup path that encloses nothing.
    path: PathBuf,
  },
  /// No cgroup directory was given to attach to.
  #[error("ebpf capture needs a cgroup directory to attach to, or `--ebpf-cgroup enclosing`")]
  NoCgroup,
  /// The embedded eBPF object does not load.
  #[error("load eBPF programs: {origin}")]
  LoadPrograms {
    /// Underlying loader failure.
    #[source]
    origin: EbpfError,
  },
  /// The `CONFIG` map stage fails.
  #[error("write eBPF CONFIG map: {origin}")]
  WriteConfigMap {
    /// Underlying configuration failure.
    #[source]
    origin: Box<Error>,
  },
  /// Attaching to the cgroup fails.
  #[error("attach to cgroup {path}: {origin}", path = path.display())]
  AttachCgroup {
    /// Cgroup that was attached to.
    path: PathBuf,
    /// Underlying attach failure.
    #[source]
    origin: Box<Error>,
  },
  /// The configuration refuses to write: a listen port is zero, so the
  /// programs would redirect into a closed socket.
  #[error("refusing to write an unusable CONFIG: listen ports must be non-zero")]
  ListenPortsZero,
  /// The configuration refuses to write: a bypass prefix outside `1..=32`
  /// would bypass everything (`0`) or match nothing, so it states a mistake.
  #[error("refusing to write an unusable CONFIG: bypass prefix length must be 1..=32, got {prefix}")]
  InvalidBypassPrefix {
    /// Prefix length that was rejected.
    prefix: u8,
  },
  /// The configuration refuses to write: more bypass CIDRs than the programs
  /// carry (`MAX_BYPASS`), so one would be silently dropped.
  #[error("refusing to write an unusable CONFIG: {count} bypass CIDRs exceed the programs' capacity")]
  TooManyBypasses {
    /// Bypass entries that were supplied.
    count: usize,
  },
  /// A map is missing from the eBPF object.
  #[error("{name} map missing from the eBPF object")]
  MapMissing {
    /// Map that was looked up.
    name: &'static str,
  },
  /// A map has an unexpected type.
  #[error("{name} has an unexpected type: {origin}")]
  UnexpectedMapType {
    /// Map that was converted.
    name: &'static str,
    /// Underlying conversion failure.
    #[source]
    origin: MapError,
  },
  /// The `CONFIG` entry does not write.
  #[error("write CONFIG: {origin}")]
  SetConfig {
    /// Underlying map failure.
    #[source]
    origin: MapError,
  },
  /// The `FLOW` map does not read.
  #[error("read FLOW: {origin}")]
  ReadFlow {
    /// Underlying map failure.
    #[source]
    origin: MapError,
  },
  /// The `ORIG_DST` map does not read.
  #[error("read ORIG_DST: {origin}")]
  ReadOrigDst {
    /// Underlying map failure.
    #[source]
    origin: MapError,
  },
  /// A cgroup directory does not open.
  #[error("open cgroup {path}: {origin}", path = path.display())]
  OpenCgroup {
    /// Cgroup that was opened.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    origin: IoError,
  },
  /// A program is missing from the eBPF object.
  #[error("{name} program missing from the eBPF object")]
  ProgramMissing {
    /// Program that was looked up.
    name: String,
  },
  /// A program has an unexpected type.
  #[error("{name} has an unexpected type: {origin}")]
  UnexpectedProgramType {
    /// Program that was converted.
    name: String,
    /// Underlying conversion failure.
    #[source]
    origin: ProgramError,
  },
  /// A program does not load.
  #[error("load {name}: {origin}")]
  LoadProgram {
    /// Program that was loaded.
    name: String,
    /// Underlying loader failure.
    #[source]
    origin: ProgramError,
  },
  /// A program does not attach.
  #[error("attach {name}: {origin}")]
  AttachProgram {
    /// Program that was attached.
    name: String,
    /// Underlying attach failure.
    #[source]
    origin: ProgramError,
  },
}
