No vulnerability found for this question.

All host/IP filtering mechanisms found in the codebase—`host_filtering` in [1](#0-0) , the `NetworkParams::no_private_ip`/`allow_private_ip` flags in [2](#0-1) , `DiscoveryBehaviour`'s private-IP filtering in [3](#0-2) , and `TelemetryEndpoints`/`url_to_multiaddr` parsing in [4](#0-3) —are node-operator/CLI configuration concerns, not runtime entry points reachable by an unprivileged attacker via a signed extrinsic, contract call, or XCM message. They gate node-to-node networking or client-side RPC/telemetry behavior configured by the node operator, not attacker-controlled payloads processed by FRAME pallets, the contracts/revive pallet, or the XCM executor.

The Grafana CVE-2023-4399 bug class (a deny-list host filter bypassed via punycode-encoded hostnames in an admin-configured "Request security" feature) has no analogous on-chain, attacker-reachable invariant in this codebase: there is no deny-list of destination hosts/addresses that gates a permitted extrinsic, contract call, or XCM instruction where an attacker could smuggle an alternate encoding of a blocked identifier past a check. The closest structural analogs (RPC host filter, private-IP address filtering, telemetry URL parsing) are all off-chain, config-only, or node-operator-controlled, which the report's method explicitly excludes as non-eligible (privileged prerequisites, config-only, dependency-only).

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

**File:** substrate/client/cli/src/params/network_params.rs (L93-112)
```rust
	/// Always forbid connecting to private IPv4/IPv6 addresses.
	///
	/// The option doesn't apply to addresses passed with `--reserved-nodes` or
	/// `--bootnodes`. Enabled by default for chains marked as "live" in their chain
	/// specifications.
	///
	/// Address allocation for private networks is specified by
	/// [RFC1918](https://tools.ietf.org/html/rfc1918)).
	#[arg(long, alias = "no-private-ipv4", conflicts_with_all = &["allow_private_ip"])]
	pub no_private_ip: bool,

	/// Always accept connecting to private IPv4/IPv6 addresses.
	///
	/// Enabled by default for chains marked as "local" in their chain specifications,
	/// or when `--dev` is passed.
	///
	/// Address allocation for private networks is specified by
	/// [RFC1918](https://tools.ietf.org/html/rfc1918)).
	#[arg(long, alias = "allow-private-ipv4", conflicts_with_all = &["no_private_ip"])]
	pub allow_private_ip: bool,
```

**File:** substrate/client/network/src/discovery.rs (L754-760)
```rust
			if !self.allow_private_ip {
				list_to_filter.retain(|addr| match addr.iter().next() {
					Some(Protocol::Ip4(addr)) if !IpNetwork::from(addr).is_global() => false,
					Some(Protocol::Ip6(addr)) if !IpNetwork::from(addr).is_global() => false,
					_ => true,
				});
			}
```

**File:** substrate/client/telemetry/src/endpoints.rs (L58-74)
```rust
/// Parses a WebSocket URL into a libp2p `Multiaddr`.
fn url_to_multiaddr(url: &str) -> Result<Multiaddr, multiaddr::Error> {
	// First, assume that we have a `Multiaddr`.
	let parse_error = match url.parse() {
		Ok(ma) => return Ok(ma),
		Err(err) => err,
	};

	// If not, try the `ws://path/url` format.
	if let Ok(ma) = multiaddr::from_url(url) {
		return Ok(ma);
	}

	// If we have no clue about the format of that string, assume that we were expecting a
	// `Multiaddr`.
	Err(parse_error)
}
```
