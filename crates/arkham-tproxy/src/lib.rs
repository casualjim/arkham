//! Kernel TPROXY capture backend: nftables rules plus policy routes feeding
//! an `IP_TRANSPARENT` listener.

mod error;
mod nft;
mod route;

mod tproxy;

pub use error::Error;
pub use tproxy::{EGRESS_MARK, FWMARK, run_tproxy};
