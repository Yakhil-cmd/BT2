No vulnerability found for this question.

The reported CVE concerns SSRF via address-representation bypass in AWS SSM Agent's port-forwarding feature, an unrelated network daemon. Searching the Polkadot SDK for comparable "destination denylist" / address-validation logic only surfaces node-level networking code — libp2p/litep2p discovery address filtering (`can_add_to_dht`, `is_new_external_address`) [1](#0-0) [2](#0-1) , authority-discovery address publishing filters [3](#0-2) , CLI network params like `--no-private-ip`/`--allow-private-ip` [4](#0-3) , WebRTC address validation [5](#0-4) , and the offchain-worker HTTP request API [6](#0-5) .

None of these constitute a real, unprivileged, remote-user-reachable entry point of the kind required by the analysis method (signed extrinsic, enabled contract call, permitted XCM execute/send, or public proof submission):
- The network/discovery address filters are peer-to-peer transport concerns configured by node operators, not driven by any extrinsic payload or attacker-supplied on-chain data.
- The offchain HTTP API is used by offchain workers running code chosen/deployed by the node operator, not attacker-controlled remote input.
- There is no on-chain pallet, XCM transactor, or contract precompile in this codebase that takes a destination host/URL from a transaction and performs an outbound HTTP/TCP connection subject to a denylist that could be bypassed via an "equivalent address representation" (e.g., decimal/octal/hex IP encoding, IPv4-mapped IPv6, etc.).

Since the SDK has no analogous attacker-reachable "fetch this address unless denylisted" flow reachable from a signed extrinsic, contract call, or XCM message, there is no demonstrable Polkadot SDK analog to this SSRF finding.

### Citations

**File:** substrate/client/network/src/discovery.rs (L577-592)
```rust
	///
	/// This test is successful only for global IP addresses and DNS names.
	// NB: Currently all DNS names are allowed and no check for TLD suffixes is done
	// because the set of valid domains is highly dynamic and would require frequent
	// updates, for example by utilising publicsuffix.org or IANA.
	pub fn can_add_to_dht(addr: &Multiaddr) -> bool {
		let ip = match addr.iter().next() {
			Some(Protocol::Ip4(ip)) => IpNetwork::from(ip),
			Some(Protocol::Ip6(ip)) => IpNetwork::from(ip),
			Some(Protocol::Dns(_)) | Some(Protocol::Dns4(_)) | Some(Protocol::Dns6(_)) => {
				return true
			},
			_ => return false,
		};
		ip.is_global()
	}
```

**File:** substrate/client/network/src/litep2p/discovery.rs (L505-517)
```rust
	/// Can `address` be added to DHT.
	fn can_add_to_dht(address: &Multiaddr) -> bool {
		let ip = match address.iter().next() {
			Some(Protocol::Ip4(ip)) => IpNetwork::from(ip),
			Some(Protocol::Ip6(ip)) => IpNetwork::from(ip),
			Some(Protocol::Dns(_)) | Some(Protocol::Dns4(_)) | Some(Protocol::Dns6(_)) => {
				return true
			},
			_ => return false,
		};

		ip.is_global()
	}
```

**File:** substrate/client/authority-discovery/src/worker.rs (L434-447)
```rust
	fn addresses_to_publish(&mut self) -> impl Iterator<Item = Multiaddr> {
		let local_peer_id = self.network.local_peer_id();
		let publish_non_global_ips = self.publish_non_global_ips;

		// Checks that the address is global.
		let address_is_global = |address: &Multiaddr| {
			address.iter().all(|protocol| match protocol {
				// The `ip_network` library is used because its `is_global()` method is stable,
				// while `is_global()` in the standard library currently isn't.
				multiaddr::Protocol::Ip4(ip) => IpNetwork::from(ip).is_global(),
				multiaddr::Protocol::Ip6(ip) => IpNetwork::from(ip).is_global(),
				_ => true,
			})
		};
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

**File:** substrate/client/network/src/webrtc.rs (L192-218)
```rust
/// Check that `address` is a bare `webrtc-direct` address.
///
/// Dns is accepted as host only if the validation is applied to a public address.
fn validate(address: &Multiaddr, public_addr: bool) -> Result<(), Error> {
	let mut iter = address.iter();

	let host_is_valid = match iter.next() {
		Some(Protocol::Ip4(_) | Protocol::Ip6(_)) => true,
		Some(Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_)) => public_addr,
		_ => false,
	};

	// `/udp/<port>/webrtc-direct` and nothing after it.
	let is_valid = host_is_valid &&
		matches!(
			(iter.next(), iter.next(), iter.next()),
			(Some(Protocol::Udp(_)), Some(Protocol::WebRTCDirect), None)
		);

	is_valid
		.then_some(())
		.ok_or_else(|| Error::InvalidWebRtcAddress { address: address.clone() })
}

pub(crate) fn validate_listen_address(address: &Multiaddr) -> Result<(), Error> {
	validate(address, false)
}
```

**File:** substrate/primitives/runtime/src/offchain/http.rs (L163-180)
```rust
impl<'a, T: Default> Request<'a, T> {
	/// Create a new Request builder with the given URL.
	pub fn new(url: &'a str) -> Self {
		Request::default().url(url)
	}

	/// Change the method of the request
	pub fn method(mut self, method: Method) -> Self {
		self.method = method;
		self
	}

	/// Change the URL of the request.
	pub fn url(mut self, url: &'a str) -> Self {
		self.url = url;
		self
	}

```
