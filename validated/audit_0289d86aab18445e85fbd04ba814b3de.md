No vulnerability found for this question.

The CVE-2021-3742 report describes an SSRF caused by a web application (Chatwoot) rendering user-uploaded SVG avatars in a browser, allowing a malicious SVG payload to trigger unauthorized server-side requests when opened. This bug class requires a web server that accepts file uploads, stores/serves them, and renders them (or has a client that fetches embedded resources) — none of which exist in the Polkadot SDK's FRAME runtime, pallets, or XCM stack.

The closest technical primitive in this codebase that performs outbound HTTP requests is the offchain worker HTTP API [1](#0-0) , exposed to runtime code via `sp_io::offchain::http_request_start` [2](#0-1)  and the high-level `Request` builder in `sp-runtime` [3](#0-2) . However, this facility:

- Is only invoked from offchain worker logic that runs as part of validated/authored node code, not from a permissionless, attacker-controlled extrinsic payload processed by a server that renders/fetches user content.
- Requires the node operator to enable offchain workers and run their own logic; there is no "browser opens attacker's uploaded file" analog — no file upload, storage, or rendering pipeline exists in FRAME/XCM.
- Has no generic pallet in the scope that takes an arbitrary URL from a signed extrinsic and passes it directly into `http_request_start`.

Since the report's root cause (unvalidated user-supplied URL rendered/fetched by a web server due to insufficient input sanitization on an uploaded file) has no structural analog reachable via a real, unprivileged runtime entry point (signed extrinsic, contract call, or XCM message) in the Polkadot SDK, forcing this into a "chain" or "pallet" narrative would be speculative and unsupported by evidence.

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

**File:** substrate/primitives/io/src/lib.rs (L1687-1700)
```rust
	/// Initiates a http request given HTTP verb and the URL.
	///
	/// Meta is a future-reserved field containing additional, parity-scale-codec encoded
	/// parameters. Returns the id of newly started request.
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
