//! Typed errors for WASM plugin load and instantiation.

use std::path::PathBuf;

use wasmtime::Error as WasmtimeError;

/// Every way plugin load and instantiation can fail.
///
/// Guest-call failures never surface here: a trap, fuel exhaustion, or epoch
/// deadline fails the connection closed via [`Verdict::Close`](crate::Verdict).
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// The WASI linker rejects a component.
  #[error("plugin `{name}`: WASI linker failed: {origin}")]
  WasiLinker {
    /// Plugin being loaded.
    name: String,
    /// Underlying linker failure.
    #[source]
    origin: WasmtimeError,
  },
  /// A component implements neither rewrite world.
  #[error("plugin `{name}` implements neither rewrite world: request: {request}; response: {response}")]
  NeitherWorld {
    /// Plugin being loaded.
    name: String,
    /// Request-world probe failure chain.
    request: String,
    /// Response-world probe failure chain.
    response: String,
  },
  /// The wasmtime engine does not build.
  #[error("plugin engine: {origin}")]
  Engine {
    /// Underlying engine failure.
    #[source]
    origin: WasmtimeError,
  },
  /// A component file cannot be read or compiled.
  #[error("plugin `{name}`: cannot load `{path}`: {origin}", path = path.display())]
  LoadComponent {
    /// Plugin being loaded.
    name: String,
    /// Component file that failed to load.
    path: PathBuf,
    /// Underlying load failure.
    #[source]
    origin: WasmtimeError,
  },
  /// The request world does not instantiate.
  #[error("plugin `{name}`: request-world instantiation failed: {origin}")]
  RequestInstantiate {
    /// Plugin being started.
    name: String,
    /// Underlying instantiation failure.
    #[source]
    origin: WasmtimeError,
  },
  /// The response world does not instantiate.
  #[error("plugin `{name}`: response-world instantiation failed: {origin}")]
  ResponseInstantiate {
    /// Plugin being started.
    name: String,
    /// Underlying instantiation failure.
    #[source]
    origin: WasmtimeError,
  },
  /// A fresh store cannot arm its fuel budget.
  #[error("arming fuel on a fresh plugin store: {origin}")]
  FuelArm {
    /// Underlying wasmtime failure.
    #[source]
    origin: WasmtimeError,
  },
}
