//! Generated bindings for the `request` rewrite world.

#![allow(missing_docs, reason = "generated code mirrors the WIT contract")]

wasmtime::component::bindgen!({
  path: "wit",
  world: "request",
  exports: { default: async },
});
