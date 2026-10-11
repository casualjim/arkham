use wit_bindgen::generate;

generate!({
  world: "request",
  path: "../../../crates/arkham-plugin/wit",
});

struct TrapRequest;

impl Guest for TrapRequest {
  fn rewrite_request_head(_head: RequestHead) -> Result<RequestHead, String> {
    unreachable!("fail-closed fixture: head hook always traps")
  }

  fn rewrite_request_trailers(headers: Vec<Header>) -> Result<Vec<Header>, String> {
    Ok(headers)
  }

  fn rewrite_request_chunk(chunk: BodyChunk) -> Result<Vec<u8>, String> {
    Ok(chunk.data)
  }
}

export!(TrapRequest);
