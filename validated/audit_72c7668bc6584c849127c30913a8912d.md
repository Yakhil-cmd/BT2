No vulnerability found for this question.

Investigation summary: The CVE describes a CIDR mask parsing flaw in Perl's `Net::CIDR::Lite` where padded octal-like prefixes (`/00`, `/01`) bypass validation. Searching the Polkadot SDK codebase for analogous CIDR/IP-mask parsing surfaces found only non-consensus, operator-controlled configuration code: the `--rpc-rate-limit-whitelisted-ips` CLI flag which parses CIDR strings via the `ip_network` crate [1](#0-0)  and the `RPC_RATE_LIMIT_WHITELISTED_IPS` key in the experimental RPC endpoint parser [2](#0-1) , plus the `can_add_to_dht` IP-range checks in the discovery module used only to filter multiaddresses for Kademlia DHT insertion [3](#0-2) .

None of these constitute a valid analog per the scan's requirements:
- All CIDR parsing found is confined to node-operator CLI configuration (`rpc-rate-limit-whitelisted-ips`) or internal P2P discovery/telemetry address handling — not a signed extrinsic, contract call, or XCM message path reachable by an unprivileged attacker.
- The parsing itself uses the external `ip_network` Rust crate rather than a custom/vulnerable CIDR implementation; there's no evidence of the specific "extraneous zero" mask-bypass defect being reproduced here.
- No FRAME pallet, XCM executor, bridge, or contracts/revive logic uses CIDR/IP-mask parsing for access control — the described invariant (IP ACL bypass via malformed prefix length) has no on-chain or runtime-security-relevant counterpart in this codebase.

Since there is no genuine user-facing entry point (extrinsic, contract call, XCM message, or proof submission) that relies on CIDR-style mask parsing for authorization, this CVE has no demonstrable analog in the Polkadot SDK's production/runtime attack surface.

### Citations

**File:** substrate/client/cli/src/params/rpc_params.rs (L87-91)
```rust
	/// Disable RPC rate limiting for certain ip addresses.
	///
	/// Each IP address must be in CIDR notation such as `1.2.3.4/24`.
	#[arg(long, num_args = 1..)]
	pub rpc_rate_limit_whitelisted_ips: Vec<IpNetwork>,
```

**File:** substrate/client/cli/src/params/rpc_params.rs (L471-476)
```rust
				RPC_RATE_LIMIT_WHITELISTED_IPS => {
					let ip: IpNetwork = val
						.parse()
						.map_err(|_| invalid_value(RPC_RATE_LIMIT_WHITELISTED_IPS, &val))?;
					rate_limit_whitelisted_ips.push(ip);
				},
```

**File:** substrate/client/network/src/discovery.rs (L582-592)
```rust
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
