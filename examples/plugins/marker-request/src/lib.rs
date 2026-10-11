use wit_bindgen::generate;

generate!({
  world: "request",
  path: "../../../crates/arkham-plugin/wit",
});

struct MarkerRequest;

impl Guest for MarkerRequest {
  fn rewrite_request_head(mut head: RequestHead) -> Result<RequestHead, String> {
    head.headers.push(Header {
      name: "x-arkham-plugin".to_string(),
      value: b"marker".to_vec(),
    });
    Ok(head)
  }

  fn rewrite_request_trailers(mut headers: Vec<Header>) -> Result<Vec<Header>, String> {
    headers.push(Header {
      name: "x-trailer-plugin".to_string(),
      value: b"marker".to_vec(),
    });
    Ok(headers)
  }

  fn rewrite_request_chunk(mut chunk: BodyChunk) -> Result<Vec<u8>, String> {
    // Mark every non-empty region: H1 calls per emitted region (eof on
    // the terminal flush, which may carry zero bytes — never rewrite an
    // empty release call), H2 once per DATA frame.
    if !chunk.data.is_empty() {
      chunk.data.extend_from_slice(b"-marked");
    }
    Ok(chunk.data)
  }
}

export!(MarkerRequest);
