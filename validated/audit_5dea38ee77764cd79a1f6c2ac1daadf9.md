No vulnerability found for this question.

The CVE describes a web-application SSRF pattern (PATH_INFO tunneling through a CGI script to force a server to issue attacker-directed HTTP requests to arbitrary intranet hosts). The closest conceptual analog in this codebase is the offchain worker HTTP API (`sp_io::offchain::http_request_start` / `sp_runtime::offchain::http::Request`), which lets runtime code issue outbound HTTP requests with a caller-supplied URI [1](#0-0) [2](#0-1) .

However, this doesn't produce a valid analog for several reasons:

- Offchain workers execute entirely outside the state-transition function: any state mutation during their execution is discarded, and the only way they can affect chain state is by submitting a normal extrinsic afterward [3](#0-2) . There is no "server-side" privileged network (intranet) being tunneled into on behalf of an untrusted remote party — the node operator's own client process is the one issuing the request, using URLs that are hard-coded in pallet/runtime logic written by trusted chain developers, not arbitrary end-user input analogous to Webmin's PATH_INFO.
- There's no real user entry point (signed extrinsic, XCM execute/send, contract call) that lets an attacker supply an arbitrary target URL into this API in production pallet code; the search only surfaces the generic HTTP client plumbing and its own test/mocked usages [4](#0-3) .
- Even if a hypothetical pallet built a URL from user-controlled storage, the resulting request has zero consensus impact (it's discarded, non-deterministic by design), so it cannot cause theft, unbacked issuance, unauthorized dispatch, or deterministic chain failure as required by the reporting criteria.

Since no reachable, attacker-controlled, consensus-relevant entry point analogous to Webmin's tunnel/link.cgi SSRF exists in the scoped production code, this does not qualify as a valid finding.

### Citations

**File:** substrate/primitives/io/src/lib.rs (L1691-1700)
```rust
	fn http_request_start(
		&mut self,
		method: PassFatPointerAndRead<&str>,
		uri: PassFatPointerAndRead<&str>,
		meta: PassFatPointerAndRead<&[u8]>,
	) -> AllocateAndReturnByCodec<Result<HttpRequestId, ()>> {
		self.extension::<OffchainWorkerExt>()
			.expect("http_request_start can be called only in the offchain worker context")
			.http_request_start(method, uri, meta)
	}
```

**File:** substrate/primitives/runtime/src/offchain/http.rs (L200-227)
```rust
impl<'a, I: AsRef<[u8]>, T: IntoIterator<Item = I>> Request<'a, T> {
	/// Send the request and return a handle.
	///
	/// Err is returned in case the deadline is reached
	/// or the request timeouts.
	pub fn send(self) -> Result<PendingRequest, HttpError> {
		let meta = &[];

		// start an http request.
		let id = sp_io::offchain::http_request_start(self.method.as_ref(), self.url, meta)
			.map_err(|_| HttpError::IoError)?;

		// add custom headers
		for header in &self.headers {
			sp_io::offchain::http_request_add_header(id, header.name(), header.value())
				.map_err(|_| HttpError::IoError)?
		}

		// write body
		for chunk in self.body {
			sp_io::offchain::http_request_write_body(id, chunk.as_ref(), self.deadline)?;
		}

		// finalize the request
		sp_io::offchain::http_request_write_body(id, &[], self.deadline)?;

		Ok(PendingRequest { id })
	}
```

**File:** docs/sdk/src/reference_docs/frame_offchain_workers.rs (L17-34)
```rust
//! Offchain workers are in principle not different in any way: It is a runtime API exposed by the
//! wasm blob ([`sp_offchain::OffchainWorkerApi`]), and the node software calls into it when it
//! deems fit. But, crucially, this API call is different in that:
//!
//! 1. It can have no impact on the state ie. it is _OFF (the) CHAIN_. If any state is altered
//!    during the execution of this API call, it is discarded.
//! 2. It has access to an extended set of host functions that allow the wasm blob to do more. For
//!    example, call into HTTP requests.
//!
//! > The main way through which an offchain worker can interact with the state is by submitting an
//! > extrinsic to the chain. This is the ONLY way to alter the state from an offchain worker.
//! > [`pallet_example_offchain_worker`] provides an example of this.
//!
//!
//! Given the "Off Chain" nature of this API, it is important to remember that calling this API is
//! entirely optional. Some nodes might call into it, some might not, and it would have no impact on
//! the execution of your blockchain because no state is altered no matter the execution of the
//! offchain worker API.
```

**File:** substrate/client/offchain/src/api/http.rs (L146-157)
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
```
