No vulnerability found for this question.

The polkadot-sdk analog to consider would be the offchain worker HTTP client, where `HttpApi::request_add_header` in [1](#0-0)  and the exposed `http_request_add_header` host function in [2](#0-1)  allow runtime/offchain-worker code to set arbitrary header values. However, unlike RestSharp's `HttpHeaders.TryAddWithoutValidation`, this code constructs headers via `hyper::header::HeaderValue::try_from(value)`, which does perform validation and rejects invalid characters (including CR/LF) before the header is appended, so the exact missing-check condition from the report does not hold here.

Beyond the missing-vulnerability condition, this path also fails the required "real user entry" criterion: offchain worker HTTP requests are node-local operations initiated by trusted offchain worker/runtime code chosen by the node operator, not something driven by an unprivileged, attacker-controlled signed extrinsic, contract call, or XCM message reaching consensus state. There is no demonstrable reachable path where an untrusted external actor supplies the header value through a permitted runtime entry point. [3](#0-2)

### Citations

**File:** substrate/client/offchain/src/api/http.rs (L186-206)
```rust
	pub fn request_add_header(
		&mut self,
		request_id: HttpRequestId,
		name: &str,
		value: &str,
	) -> Result<(), ()> {
		let request = match self.requests.get_mut(&request_id) {
			Some(&mut HttpApiRequest::NotDispatched(ref mut rq, _)) => rq,
			_ => return Err(()),
		};

		let header_name = hyper::header::HeaderName::try_from(name).map_err(drop)?;
		let header_value = hyper::header::HeaderValue::try_from(value).map_err(drop)?;
		// Note that we're always appending headers and never replacing old values.
		// We assume here that the user knows what they're doing.
		request.headers_mut().append(header_name, header_value);

		tracing::debug!(target: LOG_TARGET, id = %request_id.0, %name, %value, "Added header to request");

		Ok(())
	}
```

**File:** substrate/primitives/io/src/lib.rs (L1702-1712)
```rust
	/// Append header to the request.
	fn http_request_add_header(
		&mut self,
		request_id: PassAs<HttpRequestId, u16>,
		name: PassFatPointerAndRead<&str>,
		value: PassFatPointerAndRead<&str>,
	) -> AllocateAndReturnByCodec<Result<(), ()>> {
		self.extension::<OffchainWorkerExt>()
			.expect("http_request_add_header can be called only in the offchain worker context")
			.http_request_add_header(request_id, name, value)
	}
```
