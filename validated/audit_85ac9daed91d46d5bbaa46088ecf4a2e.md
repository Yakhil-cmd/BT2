### Title
`ProxyType::NonTransfer` fail-open deny-list permits value-moving calls on Asset Hub Rococo - (File: `cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs`)

### Summary
`ProxyType::NonTransfer` on Asset Hub Rococo is documented as "can execute any call that does not transfer funds or assets," but is implemented as a deny-list that only excludes `Balances`, `Assets`, `NftFractionalization`, `Nfts`, and `Uniques`. It fails to deny `ForeignAssets`, `PoolAssets`, `AssetConversion`, `Psm`, `PolkadotXcm`, `Revive`, `Vesting::vested_transfer`, and `Indices::transfer`/`force_transfer` — all of which move the delegator's funds/assets exactly like the already-denied calls. This is the identical bug class that was found and fixed for Asset Hub Westend (`GHSA`/PR `prdoc/pr_12771.prdoc`) and for the `staking-async` parachain runtime (`prdoc/pr_12922.prdoc`), but the fix was never back-ported to Asset Hub Rococo.

### Finding Description
`InstanceFilter<RuntimeCall>::filter` for `ProxyType::NonTransfer` is implemented as: [1](#0-0) 

This deny-list based filter "fails open": any pallet added to the runtime, or any pallet not explicitly enumerated, is reachable by a `NonTransfer` proxy. `pallet_proxy::do_proxy` installs `def.proxy_type.filter(c)` as the call filter for the derived proxy origin and then dispatches the call unfiltered otherwise: [2](#0-1) 

The equivalent filter on Asset Hub Westend was already found to leak value-moving calls through `ForeignAssets`, `PoolAssets`, `AssetConversion`, `Psm`, `PolkadotXcm`, `Revive`, and `Indices::transfer`/`force_transfer`, and was patched to explicitly deny them: [3](#0-2) [4](#0-3) 

Asset Hub Rococo runs the same set of pallets — `ForeignAssets`, `PoolAssets`, `AssetConversion`, `Psm`, `PolkadotXcm`, `Revive`, `Vesting`, `Indices` are all present in its runtime — yet its `NonTransfer` filter was never updated to match the Westend fix; it still only denies `Balances { .. } | Assets { .. } | NftFractionalization { .. } | Nfts { .. } | Uniques { .. }`. Consequently a `NonTransfer` proxy on Asset Hub Rococo can dispatch, for example, `ForeignAssets::transfer`, `PoolAssets::transfer`, `AssetConversion::swap_exact_tokens_for_tokens`, `Psm::mint`/`redeem`, `PolkadotXcm::transfer_assets`/`teleport_assets`, `Revive::call` with nonzero `value`, `Vesting::vested_transfer`, and `Indices::transfer`/`force_transfer` — every one of which moves the delegator's funds/assets, contradicting the documented and intended semantics of the `NonTransfer` proxy type.

The root cause parallels the Avo report's pattern precisely: a permission/authorization check is scoped incorrectly (a global/incomplete deny-list instead of an allow-list bound to the intended capability), so an action ("call"/"resource") that should be out-of-scope for the caller's granted permission (proxy type) is nonetheless dispatched, because the check fails open for anything not explicitly enumerated.

### Impact Explanation
Any account that has been granted a `NonTransfer` proxy — a delegation explicitly intended to exclude fund/asset movement (e.g., granted to a semi-trusted bot, watcher, or automation key) — can move the delegator's funds and assets via `ForeignAssets`, `PoolAssets`, `AssetConversion`, `Psm`, `PolkadotXcm`, `Revive` (value transfer), `Vesting::vested_transfer`, and `Indices::transfer`/`force_transfer`. This breaks the delegator's authorization model and can result in theft/unauthorized transfer of the delegator's assets by a proxy holder who was never granted that capability — a Broken Access Control impact matching CWE-284/CWE-639 in the source report. Severity is High for the affected proxy delegators, though scope is bounded to accounts that use `NonTransfer` proxies on Asset Hub Rococo (a testnet), which affects eligibility/severity weighting versus a mainnet analog (Asset Hub Westend/Polkadot equivalent already fixed).

### Likelihood Explanation
No privileged role or governance action is required. Any account that already delegated a `NonTransfer` proxy (a normal, documented, self-service `pallet_proxy::add_proxy` action available to any signed origin) is immediately affected — the delegate proxy account can dispatch the under-filtered calls at will. The bug is purely a runtime configuration defect (missing match arms), directly reachable through the standard `Proxy::proxy` extrinsic with no attacker-controlled inputs beyond selecting which `RuntimeCall` variant to wrap.

### Recommendation
Apply the same fix already merged for Asset Hub Westend (`prdoc/pr_12771.prdoc`) to Asset Hub Rococo's `ProxyType::NonTransfer` filter: explicitly deny `ForeignAssets`, `PoolAssets`, `AssetConversion`, `Psm`, `PolkadotXcm`, `Revive`, `Vesting::vested_transfer`, and `Indices::transfer`/`force_transfer`, mirroring the Westend implementation at [3](#0-2) . More durably, add the same lattice/regression tests that now exist for Westend (`non_transfer_proxy_rejects_value_moving_calls`, `proxy_type_superset_relation_matches_call_filters`) to Asset Hub Rococo's test suite so future pallet additions cannot silently reopen this fail-open deny-list.

### Proof of Concept
No PoC execution was run (per method constraints, no test was claimed as executed). Static evidence:
- Asset Hub Rococo's `NonTransfer` filter denies only `Balances`/`Assets`/`NftFractionalization`/`Nfts`/`Uniques`: [1](#0-0) 
- The pallets `ForeignAssets`, `PoolAssets`, `AssetConversion`, `Psm`, `PolkadotXcm`, `Revive` are configured in the same runtime file (confirmed present via repository search), matching the exact call families the Westend fix had to deny.
- `pallet_proxy::do_proxy` dispatches the wrapped call using `def.proxy_type.filter(c)` as the only gate before dispatch: [2](#0-1) 
- A minimal integration reproduction (not executed here) would: (1) `Proxy::add_proxy(delegator, delegate, ProxyType::NonTransfer, 0)`, (2) from `delegate`, call `Proxy::proxy(delegator, None, Box::new(RuntimeCall::ForeignAssets(pallet_assets::Call::transfer{..})))`, and (3) observe `ProxyExecuted { result: Ok(()) }` rather than `CallFiltered`, exactly as the analogous Westend regression test `non_transfer_proxy_rejects_value_moving_calls` demonstrates for the pre-fix Westend code: [5](#0-4)

### Citations

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

**File:** substrate/frame/proxy/src/lib.rs (L994-1026)
```rust
	fn do_proxy(
		def: ProxyDefinition<T::AccountId, T::ProxyType, BlockNumberFor<T>>,
		real: T::AccountId,
		call: <T as Config>::RuntimeCall,
	) {
		use frame::traits::{InstanceFilter as _, OriginTrait as _};
		// This is a freshly authenticated new account, the origin restrictions doesn't apply.
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
		let e = call.dispatch(origin);
		Self::deposit_event(Event::ProxyExecuted { result: e.map(|_| ()).map_err(|e| e.error) });
	}
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

**File:** prdoc/pr_12771.prdoc (L1-28)
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
crates:
- name: asset-hub-westend-runtime
  bump: patch
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L2642-2668)
```rust
/// Regression test for <https://github.com/paritytech/polkadot-sdk/issues/12466>.
///
/// `ProxyType::NonTransfer` is documented as permitting "any call that does not transfer funds or
/// assets", but it is implemented as a deny-list and so fails open. `ForeignAssets` and
/// `PoolAssets` transfers were reachable, as were swaps, XCM transfers, contract calls carrying a
/// value, and index transfers (which repatriate the reserved deposit).
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
