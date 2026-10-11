//! Per-world generated component bindings.
//!
//! The two worlds share WIT record shapes but `bindgen!` emits distinct
//! Rust types per world, so each world lives in its own module.

pub mod request;
pub mod response;
