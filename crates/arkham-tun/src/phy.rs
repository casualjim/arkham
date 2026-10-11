//! smoltcp device over packet queues: TUN ingress bytes in, egress packets out.

use std::collections::VecDeque;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

pub(crate) const TUN_MTU: u16 = 1500;

#[derive(Default)]
pub(crate) struct TunPhy {
  pub(super) rx: VecDeque<Vec<u8>>,
  pub(super) tx: VecDeque<Vec<u8>>,
}

pub(crate) struct TunRx(Vec<u8>);
pub(crate) struct TunTx<'a>(&'a mut VecDeque<Vec<u8>>);

impl Device for TunPhy {
  type RxToken<'a> = TunRx;
  type TxToken<'a> = TunTx<'a>;

  fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
    let packet = self.rx.pop_front()?;
    Some((TunRx(packet), TunTx(&mut self.tx)))
  }

  fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
    Some(TunTx(&mut self.tx))
  }

  fn capabilities(&self) -> DeviceCapabilities {
    let mut caps = DeviceCapabilities::default();
    caps.medium = Medium::Ip;
    caps.max_transmission_unit = usize::from(TUN_MTU);
    caps
  }
}

impl RxToken for TunRx {
  fn consume<R, F>(self, f: F) -> R
  where
    F: FnOnce(&[u8]) -> R,
  {
    f(&self.0)
  }
}

impl TxToken for TunTx<'_> {
  fn consume<R, F>(self, len: usize, f: F) -> R
  where
    F: FnOnce(&mut [u8]) -> R,
  {
    let mut buf = vec![0u8; len];
    let result = f(&mut buf);
    self.0.push_back(buf);
    result
  }
}
