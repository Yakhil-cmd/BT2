No vulnerability found for this question.

The reported CVE (GHSA-vwpg-f6gw-rjvf / CVE-2021-22113) concerns Spring Cloud Netflix Zuul's "Sensitive Headers" restriction being bypassed via specially crafted URLs in an HTTP reverse-proxy component. I searched for an analogous authorization-bypass-via-header/URL-crafting pattern in `polkadot-sdk`'s HTTP-adjacent surfaces (RPC server host filtering, CORS, proxy-IP trust, and the offchain-worker HTTP client), and none of them constitute a comparable authorization bypass reachable through a permissionless on-chain entry point.

What exists in this codebase in the HTTP-header space is node-operator-configured infrastructure, not runtime/extrinsic logic:
- `substrate/client/rpc-servers/src/utils.rs` `get_proxy_ip` parses `Forwarded`/`X-Forwarded-For`/`X-Real-Ip` only when the node operator explicitly opts in via `--rpc-rate-limit-trust-proxy-headers`, and this only affects rate-limit bucketing, not authorization of RPC method safety (`substrate/client/cli/src/params/rpc_params.rs:93-101`, `substrate/client/rpc-servers/src/utils.rs:249-286`). [1](#0-0) [2](#0-1) 
- The actual RPC "unsafe method" authorization is governed by `DenyUnsafe`/`check_if_safe` set as a request extension per-connection based on listen-address/local-vs-external classification, independent of any header values, so it cannot be bypassed by header/URL crafting the way Zuul's sensitive-header stripping could be. [3](#0-2) [4](#0-3) 
- `NodeHealthProxy` in `substrate/client/rpc-servers/src/middleware/node_health.rs` only rewrites `/health` and `/health/readiness` GET requests into an internal `system_health` JSON-RPC call; it does not forward or strip any client-supplied sensitive headers to a backend. [5](#0-4) 
- The offchain-worker HTTP client (`substrate/client/offchain/src/api/http.rs`, `substrate/primitives/runtime/src/offchain/http.rs`) lets runtime code (via offchain workers) set arbitrary outgoing headers, but this is an outbound request built by trusted node-side offchain worker code, not an attacker-controlled inbound proxy path, and offchain workers do not have on-chain authorization implications analogous to Zuul's header-stripping bypass. [6](#0-5) 

None of these are reachable through a signed extrinsic, contract call, or XCM message as required by the analysis methodology, and none involve stripping/bypassing a security-relevant header check the way the Zuul vulnerability does. There is no comparable "Sensitive Headers" authorization mechanism in the FRAME runtime, pallets, or XCM executor that could be bypassed via crafted request paths.

### Citations

**File:** substrate/client/rpc-servers/src/utils.rs (L255-286)
```rust
pub(crate) fn get_proxy_ip<B>(req: &http::Request<B>) -> Option<IpAddr> {
	if let Some(ip) = req
		.headers()
		.get(&FORWARDED)
		.and_then(|v| v.to_str().ok())
		.and_then(|v| ForwardedHeaderValue::from_forwarded(v).ok())
		.and_then(|v| v.remotest_forwarded_for_ip())
	{
		return Some(ip);
	}

	if let Some(ip) = req
		.headers()
		.get(&X_FORWARDED_FOR)
		.and_then(|v| v.to_str().ok())
		.and_then(|v| ForwardedHeaderValue::from_x_forwarded_for(v).ok())
		.and_then(|v| v.remotest_forwarded_for_ip())
	{
		return Some(ip);
	}

	if let Some(ip) = req
		.headers()
		.get(&X_REAL_IP)
		.and_then(|v| v.to_str().ok())
		.and_then(|v| IpAddr::from_str(v).ok())
	{
		return Some(ip);
	}

	None
}
```

**File:** substrate/client/cli/src/params/rpc_params.rs (L93-101)
```rust
	/// Trust proxy headers for disable rate limiting.
	///
	/// By default the rpc server will not trust headers such `X-Real-IP`, `X-Forwarded-For` and
	/// `Forwarded` and this option will make the rpc server to trust these headers.
	///
	/// For instance this may be secure if the rpc server is behind a reverse proxy and that the
	/// proxy always sets these headers.
	#[arg(long)]
	pub rpc_rate_limit_trust_proxy_headers: bool,
```

**File:** substrate/client/rpc-api/src/policy.rs (L26-52)
```rust
/// Checks if the RPC call is safe to be called externally.
pub fn check_if_safe(ext: &jsonrpsee::Extensions) -> Result<(), UnsafeRpcError> {
	match ext.get::<DenyUnsafe>().map(|deny_unsafe| deny_unsafe.check_if_safe()) {
		Some(Ok(())) => Ok(()),
		Some(Err(e)) => Err(e),
		None => unreachable!("DenyUnsafe extension is always set by the substrate rpc server; qed"),
	}
}

/// Signifies whether a potentially unsafe RPC should be denied.
#[derive(Clone, Copy, Debug)]
pub enum DenyUnsafe {
	/// Denies only potentially unsafe RPCs.
	Yes,
	/// Allows calling every RPCs.
	No,
}

impl DenyUnsafe {
	/// Returns `Ok(())` if the RPCs considered unsafe are safe to call,
	/// otherwise returns `Err(UnsafeRpcError)`.
	pub fn check_if_safe(self) -> Result<(), UnsafeRpcError> {
		match self {
			DenyUnsafe::Yes => Err(UnsafeRpcError),
			DenyUnsafe::No => Ok(()),
		}
	}
```

**File:** substrate/client/rpc-servers/src/lib.rs (L327-358)
```rust
		let deny_unsafe = deny_unsafe(&local_addr, &rpc_methods);

		rpc_handle.spawn(async move {
			loop {
				let (sock, remote_addr) = tokio::select! {
					res = listener.accept() => {
						match res {
							Ok(s) => s,
							Err(e) => {
								log::debug!(target: "rpc", "Failed to accept connection: {:?}", e);
								continue;
							}
						}
					}
					_ = cfg.stop_handle.clone().shutdown() => break,
				};

				let ip = remote_addr.ip();
				let cfg2 = cfg.clone();
				let service_builder2 = service_builder.clone();
				let rate_limit_whitelisted_ips2 = rate_limit_whitelisted_ips.clone();

				let svc =
					tower::service_fn(move |mut req: http::Request<hyper::body::Incoming>| {
						req.extensions_mut().insert(deny_unsafe);

						let PerConnection { methods, metrics, tokio_handle, stop_handle } =
							cfg2.clone();
						let service_builder = service_builder2.clone();

						let proxy_ip =
							if rate_limit_trust_proxy_headers { get_proxy_ip(&req) } else { None };
```

**File:** substrate/client/rpc-servers/src/middleware/node_health.rs (L78-95)
```rust
	fn call(&mut self, req: http::Request<hyper::body::Incoming>) -> Self::Future {
		let mut req = req.map(|body| HttpBody::new(body));
		let maybe_intercept = InterceptRequest::from_http(&req);

		// Modify the request and proxy it to `system_health`
		if let InterceptRequest::Health | InterceptRequest::Readiness = maybe_intercept {
			// RPC methods are accessed with `POST`.
			*req.method_mut() = Method::POST;
			// Precautionary remove the URI.
			*req.uri_mut() = Uri::from_static("/");

			// Requests must have the following headers:
			req.headers_mut().insert(http::header::CONTENT_TYPE, HEADER_VALUE_JSON);
			req.headers_mut().insert(http::header::ACCEPT, HEADER_VALUE_JSON);

			// Adjust the body to reflect the method call.
			req = req.map(|_| HttpBody::from(RPC_SYSTEM_HEALTH_CALL));
		}
```

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
