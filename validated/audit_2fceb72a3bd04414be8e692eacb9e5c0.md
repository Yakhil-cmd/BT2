No vulnerability found for this question.

The curl CVE's failure mechanism is specific to libcurl's internal HTTP Digest authentication implementation: a persistent `data->state.digest` struct that survives across `curl_easy_perform()` calls on a reused handle, silently reapplying a previous origin's realm/nonce/credentials to a new, unrelated origin. That precondition — an internal library-managed authentication *session state* that outlives a single request and gets implicitly reattached to a different trust boundary without being told to do so — does not have a reachable equivalent in this codebase.

I checked the one place where this repository plays a similar role (an HTTP client embedded in the runtime-adjacent code): the offchain-worker HTTP client in `substrate/client/offchain/src/api/http.rs` and `substrate/primitives/runtime/src/offchain/http.rs`. It has no notion of HTTP authentication at all — it is a bare hyper-based request/response bridge. Headers are supplied explicitly per-request by the offchain worker code via `Request::add_header` / `http_request_add_header`, and each call to `HttpApi::request_start` builds a brand-new `hyper::Request` with a fresh `FnvHashMap` entry keyed by a newly allocated `HttpRequestId`; there is no cached realm/nonce/HA1 or any other credential material retained between requests to be replayed against a different `uri`. [1](#0-0) [2](#0-1) 

More broadly, this repository is not an HTTP client library; the request scope centers on signed extrinsics, XCM messages, and contract calls, none of which have an analogous "session/handle reused across trust boundaries with cached authentication material" pattern — FRAME dispatch is stateless per-call at the runtime level (each extrinsic is independently validated and origin-checked via `frame_system`/signed extensions), and XCM origin conversion is derived fresh from the message's declared origin rather than cached from a prior unrelated message. No entry point (signed extrinsic, contract call, or XCM instruction) reuses a prior "authentication" artifact from one counterparty against a different one, so the report's violated invariant has no reachable analog here.

### Citations

**File:** substrate/client/offchain/src/api/http.rs (L146-183)
```rust
impl HttpApi {
	/// Mimics the corresponding method in the offchain API.
	pub fn request_start(&mut self, method: &str, uri: &str) -> Result<HttpRequestId, ()> {
		// Start by building the prototype of the request.
		// We do this first so that we don't touch anything in `self` if building the prototype
		// fails.
		let (body_sender, receiver) = mpsc::channel(0);
		let body = StreamBody::new(receiver);
		let body = BoxBody::new(body);
		let mut request = hyper::Request::new(body);
		*request.method_mut() = hyper::Method::from_bytes(method.as_bytes()).map_err(|_| ())?;
		*request.uri_mut() = hyper::Uri::from_maybe_shared(uri.to_owned()).map_err(|_| ())?;

		let new_id = self.next_id;
		debug_assert!(!self.requests.contains_key(&new_id));
		match self.next_id.0.checked_add(1) {
			Some(new_id) => self.next_id.0 = new_id,
			None => {
				tracing::error!(
					target: LOG_TARGET,
					"Overflow in offchain worker HTTP request ID assignment"
				);
				return Err(());
			},
		};
		self.requests
			.insert(new_id, HttpApiRequest::NotDispatched(request, body_sender));

		tracing::trace!(
			target: LOG_TARGET,
			id = %new_id.0,
			%method,
			%uri,
			"Requested started",
		);

		Ok(new_id)
	}
```

**File:** substrate/primitives/runtime/src/offchain/http.rs (L120-153)
```rust
/// An HTTP request builder.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Request<'a, T = Vec<&'static [u8]>> {
	/// Request method
	pub method: Method,
	/// Request URL
	pub url: &'a str,
	/// Body of the request
	pub body: T,
	/// Deadline to finish sending the request
	pub deadline: Option<Timestamp>,
	/// Request list of headers.
	headers: Vec<header::Header>,
}

impl<T: Default> Default for Request<'static, T> {
	fn default() -> Self {
		Request {
			method: Method::Get,
			url: "http://localhost",
			headers: Vec::new(),
			body: Default::default(),
			deadline: None,
		}
	}
}

impl<'a> Request<'a> {
	/// Start a simple GET request
	pub fn get(url: &'a str) -> Self {
		Self::new(url)
	}
}

```
