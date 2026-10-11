use wit_bindgen::generate;

generate!({
  world: "response",
  path: "../../../crates/arkham-plugin/wit",
});

struct MarkerResponse;

impl Guest for MarkerResponse {
  fn rewrite_response_head(mut head: ResponseHead) -> Result<ResponseHead, String> {
    head.headers.push(Header {
      name: "x-arkham-response-plugin".to_string(),
      value: b"marker".to_vec(),
    });
    Ok(head)
  }

  fn rewrite_response_trailers(mut headers: Vec<Header>) -> Result<Vec<Header>, String> {
    headers.push(Header {
      name: "x-trailer-plugin".to_string(),
      value: b"marker".to_vec(),
    });
    Ok(headers)
  }

  fn rewrite_response_chunk(mut chunk: BodyChunk) -> Result<Vec<u8>, String> {
    // Mark every non-empty region: see marker-request (the eof release
    // call may carry zero bytes).
    if !chunk.data.is_empty() {
      chunk.data.extend_from_slice(b"-marked");
    }
    Ok(chunk.data)
  }
}

export!(MarkerResponse);
