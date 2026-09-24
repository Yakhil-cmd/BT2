No vulnerability found for this question.

The Glances advisory describes a DNS-rebinding/missing-Host-validation flaw in a Python FastAPI REST/WebUI server — a web-application transport-security issue tied to browser same-origin semantics. Searching polkadot-sdk for a genuine analog, the closest component is the substrate JSON-RPC server, which already implements host filtering: when CORS is configured, `host_filtering` installs a `HostFilterLayer` restricting requests to `localhost`, `127.0.0.1`, and `[::1]` on the bound port [1](#0-0) , and this middleware is wired into every RPC listener via `http_middleware` in `start_server` [2](#0-1) . Node operators are also explicitly warned when binding externally with unsafe methods or unspecified addresses [3](#0-2) [4](#0-3) .

Beyond the fact that this exact defense is already present (unlike Glances, which lacked it entirely), this is a node/client networking surface, not a runtime state-transition path. The analog-scan method requires a real user entry point into runtime logic — a signed extrinsic, enabled contract call, permitted XCM message, or proof submission reachable by an unprivileged attacker [5](#0-4) . There is no FRAME pallet, XCM executor, or bridge component whose "Host header"/origin validation maps onto this bug class; forcing this HTTP-transport concept onto extrinsic dispatch, XCM origin conversion, or bridge proof verification would not be a genuine analog.

### Citations

**File:** substrate/client/rpc-servers/src/utils.rs (L199-213)
```rust
pub(crate) fn host_filtering(enabled: bool, addr: SocketAddr) -> Option<HostFilterLayer> {
	if enabled {
		// NOTE: The listening addresses are whitelisted by default.

		let hosts = [
			format!("localhost:{}", addr.port()),
			format!("127.0.0.1:{}", addr.port()),
			format!("[::1]:{}", addr.port()),
		];

		Some(HostFilterLayer::new(hosts).expect("Valid hosts; qed"))
	} else {
		None
	}
}
```

**File:** substrate/client/rpc-servers/src/utils.rs (L315-322)
```rust

#[cfg(test)]
mod tests {
	use super::*;
	use hyper::header::HeaderValue;
	use jsonrpsee::server::{HttpBody, HttpRequest};

	fn request() -> http::Request<HttpBody> {
```

**File:** substrate/client/rpc-servers/src/lib.rs (L292-302)
```rust
			host_filter,
			cors,
			rate_limit,
		} = listener.rpc_settings();

		let http_middleware = tower::ServiceBuilder::new()
			.option_layer(host_filter)
			// Proxy `GET /health, /health/readiness` requests to the internal
			// `system_health` method.
			.layer(NodeHealthProxyLayer::default())
			.layer(cors);
```

**File:** substrate/client/cli/src/params/rpc_params.rs (L223-235)
```rust
		if !self.experimental_rpc_endpoint.is_empty() {
			for endpoint in &self.experimental_rpc_endpoint {
				// Technically, `0.0.0.0` isn't a public IP address, but it's a way to listen on
				// all interfaces. Thus, we consider it as a public endpoint and warn about it.
				if endpoint.rpc_methods == RpcMethods::Unsafe && endpoint.is_global() ||
					endpoint.listen_addr.ip().is_unspecified()
				{
					eprintln!(
						"It isn't safe to expose RPC publicly without a proxy server that filters \
						 available set of RPC methods."
					);
				}
			}
```

**File:** substrate/client/service/src/lib.rs (L397-406)
```rust
/// Starts RPC servers.
pub fn start_rpc_servers(
	rpc_configuration: &RpcConfiguration,
	registry: Option<&Registry>,
	tokio_handle: &Handle,
	rpc_api: RpcModule<()>,
	rpc_runtime: tokio::runtime::Runtime,
	rpc_id_provider: Option<Box<dyn sc_rpc_server::SubscriptionIdProvider>>,
) -> Result<Server, error::Error> {
	let endpoints: Vec<sc_rpc_server::RpcEndpoint> = if let Some(endpoints) =
```
