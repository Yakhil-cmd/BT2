### Title
`asset-hub-rococo` `ProxyType::NonTransfer` deny-list omits value-moving pallets that were patched on `asset-hub-westend` - ([File: cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs])

### Summary
`asset-hub-rococo`'s `ProxyType::NonTransfer` filter is documented as "can execute any call that does not transfer funds or assets," but is implemented as a deny-list that only excludes `Balances`, `Assets`, `NftFractionalization`, `Nfts` and `Uniques`. The exact same class of bug was found and fixed on `asset-hub-westend` (PR docs `prdoc/pr_12771.prdoc`) and on the `staking-async` parachain runtime (`prdoc/pr_12922.prdoc`), which additionally denied `ForeignAssets`, `PoolAssets`, `AssetConversion`, `Psm`, `PolkadotXcm`, `Revive`, `Vesting::vested_transfer` and `Indices::transfer`/`force_transfer`. `asset-hub-rococo` was never given the equivalent fix, so a `NonTransfer` proxy delegate on Rococo's Asset Hub can move the delegator's value through any of these still-unfiltered pallets, contradicting the documented "no fund/asset transfer" guarantee.

### Finding Description
`pallet_proxy::do_proxy` authorizes the proxied call solely by calling `def.proxy_type.filter(c)` [1](#0-0) . On `asset-hub-rococo`, `ProxyType::NonTransfer::filter` is a deny-list that fails open — any pallet call not explicitly matched is admitted: [2](#0-1) 

Compare this to the fixed `asset-hub-westend` filter, which explicitly denies `ForeignAssets`, `PoolAssets`, `AssetConversion`, `Psm`, `PolkadotXcm`, `Revive`, `Scheduler`, `Treasury`, `Vesting::vested_transfer`, `Indices::transfer`/`force_transfer`, `ConvictionVoting`, `Referenda`, and `Whitelist`: [3](#0-2) 

The commit history documents this exact remediation and its rationale: [4](#0-3) 

`asset-hub-rococo`'s runtime does instantiate `ForeignAssets`, `PoolAssets`, `AssetConversion`, `Psm`, `PolkadotXcm`, `Revive`, `Vesting`, `Indices` (124 matches for these pallet/type names in the file), yet its `NonTransfer` filter was not updated to deny them. A `NonTransfer` proxy delegate can therefore invoke, e.g., `RuntimeCall::PolkadotXcm(pallet_xcm::Call::transfer_assets { .. })`, `RuntimeCall::ForeignAssets(...)`, `RuntimeCall::AssetConversion(...)`, `RuntimeCall::Psm(...)`, or `RuntimeCall::Revive(...)` (contract calls carrying a `value`) on behalf of the proxied account, moving the delegator's funds/assets even though the delegator granted only the "no transfer" permission level.

This is a direct analog of the Velociraptor CVE-2025-6264 bug class: a capability (proxy-restricted, low-privilege delegation) that is supposed to exclude a dangerous action (fund transfer / arbitrary configuration change) fails to enforce that restriction because the enumeration of "dangerous" operations is incomplete — the check exists but does not cover all the surfaces that were later added to the system.

### Impact Explanation
Any account that has been delegated a `NonTransfer` proxy on `asset-hub-rococo` — a normal, unprivileged, non-custodial delegation intended to allow non-transfer actions (e.g., governance/administration on behalf of the delegator) — can drain or move the delegator's `ForeignAssets`, `PoolAssets`, or swap/redeem the delegator's assets via `AssetConversion`/`Psm`, teleport/reserve-transfer the delegator's assets off-chain via `PolkadotXcm`, or call `pallet_revive` contracts with value. This breaches the confidentiality/integrity guarantee of the proxy delegation and can result in direct loss of the delegator's funds without further authorization. Severity is comparable to the reference Medium-severity CVE: a permitted, lower-privilege actor obtains an unintended higher-privilege capability (fund movement) due to an incomplete deny-list.

### Likelihood Explanation
Likelihood is high for any account that legitimately holds a `NonTransfer` proxy relationship on `asset-hub-rococo` (a common, documented delegation pattern) — no privileged role, governance action, or stolen keys are required; the attacker only needs to already be a `NonTransfer` proxy delegate (a normal, permitted relationship the delegator itself grants) and to dispatch `pallet_proxy::proxy` wrapping one of the unfiltered calls. This mirrors the Velociraptor precondition ("must already have access to collect artifacts... typically via the Investigator role") — the attacker is a legitimately-scoped, lower-privileged party abusing an incomplete check, not an external unauthenticated party.

### Recommendation
Apply the same fix already shipped for `asset-hub-westend` (`prdoc/pr_12771.prdoc`) to `asset-hub-rococo`: extend `ProxyType::NonTransfer::filter` to explicitly deny `RuntimeCall::ForeignAssets`, `RuntimeCall::PoolAssets`, `RuntimeCall::AssetConversion`, `RuntimeCall::Psm`, `RuntimeCall::PolkadotXcm`, `RuntimeCall::Revive`, `RuntimeCall::Vesting(pallet_vesting::Call::vested_transfer { .. })`, and `RuntimeCall::Indices(pallet_indices::Call::transfer{..}/force_transfer{..})`, matching the westend implementation. Longer term, replace the deny-list pattern with an allow-list (or add the regression test `non_transfer_proxy_rejects_value_moving_calls`-equivalent, already present for `asset-hub-westend`, to `asset-hub-rococo`'s test suite) so that newly-added pallets do not silently become reachable by `NonTransfer` proxies by default.

### Proof of Concept
Not executed against a live network. Reproduction path (mirrors the existing `asset-hub-westend` regression test structure) would be:
1. In `asset-hub-rococo`'s runtime test harness, construct `ProxyType::NonTransfer.filter(&RuntimeCall::PolkadotXcm(pallet_xcm::Call::transfer_assets { .. }))` (or the `ForeignAssets`/`AssetConversion`/`Psm`/`Revive` equivalents) and assert it returns `false`.
2. Current code returns `true` (the call is admitted) because none of these variants appear in the `!matches!(...)` deny-list at `cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs:608-615`.
3. Confirm via `pallet_proxy::proxy(RuntimeOrigin::signed(delegate), real, None, Box::new(xcm_transfer_call))` that the call dispatches (`ProxyExecuted { result: Ok(()) }`) rather than being rejected with `CallFiltered`, analogous to the asserts in `asset-hub-westend`'s `non_transfer_proxy_rejects_value_moving_calls` test [5](#0-4) .

I was not able to run this test against `asset-hub-rococo` directly (no test execution environment available here); the analog is established by direct code comparison against the already-committed and documented fix for the identical bug on the sibling `asset-hub-westend` runtime and the `staking-async` parachain runtime.

### Citations

**File:** substrate/frame/proxy/src/lib.rs (L1001-1023)
```rust
		let mut origin: T::RuntimeOrigin = frame_system::RawOrigin::Signed(real).into();
		origin.add_filter(move |c: &<T as frame_system::Config>::RuntimeCall| {
			let c = <T as Config>::RuntimeCall::from_ref(c);
			// We make sure the proxy call does access this pallet to change modify proxies.
			match c.is_sub_type() {
				// Proxy call cannot add or remove a proxy with more permissions than it already
				// has.
				Some(Call::add_proxy { ref proxy_type, .. }) |
				Some(Call::remove_proxy { ref proxy_type, .. })
					if !def.proxy_type.is_superset(proxy_type) =>
				{
					false
				},
				// Proxy call cannot remove all proxies or kill pure proxies unless it has full
				// permissions.
				Some(Call::remove_proxies { .. }) | Some(Call::kill_pure { .. })
					if def.proxy_type != T::ProxyType::default() =>
				{
					false
				},
				_ => def.proxy_type.filter(c),
			}
		});
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs (L605-615)
```rust
	fn filter(&self, c: &RuntimeCall) -> bool {
		match self {
			ProxyType::Any => true,
			ProxyType::NonTransfer => !matches!(
				c,
				RuntimeCall::Balances { .. } |
					RuntimeCall::Assets { .. } |
					RuntimeCall::NftFractionalization { .. } |
					RuntimeCall::Nfts { .. } |
					RuntimeCall::Uniques { .. }
			),
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/lib.rs (L826-860)
```rust
			// NOTE: This is a deny-list, so it fails open: a pallet added to the runtime is
			// reachable by a `NonTransfer` proxy unless it is listed here. Every call family that
			// can move the delegator's funds or assets must therefore be denied explicitly.
			ProxyType::NonTransfer => !matches!(
				c,
				RuntimeCall::Balances { .. } |
					RuntimeCall::Assets { .. } |
					// The other `pallet-assets` instances transfer value just like `Assets` does.
					RuntimeCall::ForeignAssets { .. } |
					RuntimeCall::PoolAssets { .. } |
					RuntimeCall::NftFractionalization { .. } |
					RuntimeCall::Nfts { .. } |
					RuntimeCall::Uniques { .. } |
					RuntimeCall::Scheduler(..) |
					RuntimeCall::Treasury(..) |
					// Swaps and liquidity provision move the caller's assets.
					RuntimeCall::AssetConversion(..) |
					// Minting and redeeming swap the caller's stablecoins.
					RuntimeCall::Psm(..) |
					// `transfer_assets`, `teleport_assets` and friends move assets to another
					// chain, and `send`/`execute` can express the same thing as raw XCM.
					RuntimeCall::PolkadotXcm(..) |
					// Contract calls and instantiations carry a `value` to transfer.
					RuntimeCall::Revive(..) |
					// We allow calling `vest` and merging vesting schedules, but obviously not
					// vested transfers.
					RuntimeCall::Vesting(pallet_vesting::Call::vested_transfer { .. }) |
					// Transferring an index repatriates its reserved deposit to the new owner.
					// Claiming, freeing and freezing an index are still allowed.
					RuntimeCall::Indices(pallet_indices::Call::transfer { .. }) |
					RuntimeCall::Indices(pallet_indices::Call::force_transfer { .. }) |
					RuntimeCall::ConvictionVoting(..) |
					RuntimeCall::Referenda(..) |
					RuntimeCall::Whitelist(..)
			),
```

**File:** prdoc/pr_12771.prdoc (L1-25)
```text
title: 'asset-hub-westend: deny value-moving calls to the `NonTransfer` proxy'
doc:
- audience: Runtime User
  description: |-
    On Asset Hub Westend, the `ProxyType::NonTransfer` call filter is a deny-list and so fails
    open: any pallet added to the runtime is reachable by a `NonTransfer` proxy unless it is
    listed explicitly. Several call families that move the delegator's funds or assets were not
    listed, contradicting the documented policy that this proxy type can only execute calls that
    do not transfer funds or assets.

    The following are now denied to a `NonTransfer` proxy:

    - `ForeignAssets` and `PoolAssets` (the other `pallet-assets` instances), which transfer
      value exactly as `Assets` does
    - `AssetConversion`, whose swaps and liquidity operations move the caller's assets
    - `Psm`, whose mint and redeem swap the caller's stablecoins
    - `PolkadotXcm`, whose `transfer_assets`/`teleport_assets` move assets to another chain and
      whose `send`/`execute` can express the same as raw XCM
    - `Revive`, whose contract calls and instantiations carry a `value` to transfer
    - `Indices::transfer` and `Indices::force_transfer`, which repatriate the index's reserved
      deposit to the new owner

    Calls that do not move value are unaffected, including `Indices::claim`/`free`/`freeze` and
    `Vesting::vest`, as are the call families backing the proxy types that `NonTransfer` declares
    as its subsets.
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L2648-2668)
```rust
#[test]
fn non_transfer_proxy_rejects_value_moving_calls() {
	use asset_hub_westend_runtime::ProxyType;
	use frame_support::traits::InstanceFilter;

	// Collected rather than asserted one by one, so a regression reports every call that slipped
	// through instead of only the first.
	let mut leaked = Vec::new();
	for (name, call) in value_moving_calls() {
		if ProxyType::NonTransfer.filter(&call) {
			leaked.push(name);
		}
		// The call is otherwise well-formed and reachable by a fully permissioned proxy.
		assert!(ProxyType::Any.filter(&call), "Any must permit {name}");
	}

	assert!(
		leaked.is_empty(),
		"NonTransfer must reject calls that move funds or assets, but permitted: {leaked:?}",
	);
}
```
