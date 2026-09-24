No vulnerability found for this question.

The Apache Ozone advisory describes an authorization bug in HTTP admin/metadata endpoints (Recon) that are supposed to be protected but aren't. The closest conceptual analog in the Polkadot SDK is the `DenyUnsafe` / `RpcMethods` node-RPC gating mechanism [1](#0-0) , which determines whether "unsafe" RPC methods (e.g., `system_networkState`, `babe_epochAuthorship`, `dev_getBlockStats`) are exposed based on listen address and configured `RpcMethods` policy [2](#0-1) .

However, this does not qualify as a Polkadot SDK analog under the required methodology for several reasons:

1. **No real user entry point exists.** This is node-operator configuration (CLI flags like `--rpc-external`, `--unsafe-rpc-external`, `--experimental-rpc-endpoint`), not a signed extrinsic, enabled contract call, or permitted XCM message [3](#0-2) . There is no attacker-controlled runtime payload; access is gated by the node's own binding decisions.
2. **The logic is deliberately explicit and by-design, with warnings.** `rpc_interface` explicitly errors if `--rpc-external` is combined with validator mode unless unsafe methods are intentionally enabled, and prints warnings when unsafe methods are exposed publicly [4](#0-3) . This is a documented, opt-in operator risk, not a bypassed authorization check.
3. **This is node/client configuration, not runtime/consensus logic.** The task's method explicitly requires reachability through FRAME pallets, contracts/revive, XCM, or bridge logic with measurable on-chain loss/integrity break — RPC exposure is off-chain node infrastructure and falls outside the in-scope boundaries (extrinsic validation/dispatch, XCM barriers, asset/staking math, etc.).
4. No test/mocked harness or on-chain state mutation is implicated; this is a config-only concern explicitly excluded by the reporting rules ("config-only ... findings" are to be rejected).

Given these constraints, there is no demonstrable Polkadot SDK analog meeting the required bar of a real attacker-controlled runtime entry point with measurable on-chain impact.

### Citations

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

**File:** substrate/client/rpc-servers/src/utils.rs (L288-294)
```rust
/// Get the `deny_unsafe` setting based on the address and the RPC methods exposed by the interface.
pub fn deny_unsafe(addr: &SocketAddr, methods: &RpcMethods) -> DenyUnsafe {
	match (addr.ip().is_loopback(), methods) {
		(_, RpcMethods::Unsafe) | (true, RpcMethods::Auto) => DenyUnsafe::No,
		_ => DenyUnsafe::Yes,
	}
}
```

**File:** substrate/client/cli/src/params/rpc_params.rs (L49-65)
```rust
pub struct RpcParams {
	/// Listen to all RPC interfaces (default: local).
	///
	/// Not all RPC methods are safe to be exposed publicly.
	///
	/// Use an RPC proxy server to filter out dangerous methods. More details:
	/// <https://docs.substrate.io/build/remote-procedure-calls/#public-rpc-interfaces>.
	///
	/// Use `--unsafe-rpc-external` to suppress the warning if you understand the risks.
	#[arg(long)]
	pub rpc_external: bool,

	/// Listen to all RPC interfaces.
	///
	/// Same as `--rpc-external`.
	#[arg(long)]
	pub unsafe_rpc_external: bool,
```

**File:** substrate/client/cli/src/params/rpc_params.rs (L300-326)
```rust
fn rpc_interface(
	is_external: bool,
	is_unsafe_external: bool,
	rpc_methods: RpcMethods,
	is_validator: bool,
) -> crate::Result<(Ipv4Addr, Ipv6Addr)> {
	if is_external && is_validator && rpc_methods != RpcMethods::Unsafe {
		return Err(crate::Error::Input(
			"--rpc-external option shouldn't be used if the node is running as \
			 a validator. Use `--unsafe-rpc-external` or `--rpc-methods=unsafe` if you understand \
			 the risks. See the options description for more information."
				.to_owned(),
		));
	}

	if is_external || is_unsafe_external {
		if rpc_methods == RpcMethods::Unsafe {
			eprintln!(
				"It isn't safe to expose RPC publicly without a proxy server that filters \
				 available set of RPC methods."
			);
		}

		Ok((Ipv4Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED))
	} else {
		Ok((Ipv4Addr::LOCALHOST, Ipv6Addr::LOCALHOST))
	}
```
