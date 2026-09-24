### Title
`ProxyType::NonTransfer` deny-list fails open on Asset Hub Rococo, letting a non-transfer delegate move the delegator's assets - ([File: cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs])

### Summary
`asset-hub-rococo`'s `InstanceFilter<RuntimeCall>` implementation for `ProxyType::NonTransfer` is a **deny-list**: it fails open, so any pallet not explicitly named in the `!matches!(...)` pattern is reachable by a delegate holding only the `NonTransfer` proxy type. The current list only denies `Balances`, `Assets`, `NftFractionalization`, `Nfts`, `Uniques` [1](#0-0) . This is the exact bug class that was identified and fixed for the sibling `asset-hub-westend` runtime in [pr_12771](): `ForeignAssets`, `PoolAssets`, `AssetConversion`, `Psm`, `PolkadotXcm`, `Revive`, `Vesting::vested_transfer`, and `Indices::transfer`/`force_transfer` were all missing from the westend deny-list and were subsequently added [2](#0-1) [3](#0-2) . `asset-hub-rococo`'s copy of this filter was not updated with the same fix and still contains the pre-patch deny-list.

### Finding Description
`pallet-proxy`'s `do_proxy` dispatches the wrapped call through an origin filter built directly from `ProxyType::filter`, so the correctness of a given `ProxyType` is entirely dependent on the pallet author enumerating every value-moving call family [4](#0-3) . On `asset-hub-rococo`, `ProxyType::NonTransfer` is documented as "Can execute any call that does not transfer funds or assets," yet its filter only excludes five pallets:

```rust
ProxyType::NonTransfer => !matches!(
    c,
    RuntimeCall::Balances { .. } |
        RuntimeCall::Assets { .. } |
        RuntimeCall::NftFractionalization { .. } |
        RuntimeCall::Nfts { .. } |
        RuntimeCall::Uniques { .. }
),
``` [5](#0-4) 

Grepping the same file confirms `ForeignAssets`, `PoolAssets`, `AssetConversion`, `PolkadotXcm`, and `Revive` (and `Indices`, `Vesting`) are all referenced/configured pallets in this runtime, matching the pallet set present in `asset-hub-westend` where the equivalent gap was patched. None of these value-moving call families are excluded here:
- `ForeignAssets`/`PoolAssets` — other `pallet-assets` instances that transfer value exactly like `Assets`.
- `AssetConversion` — swaps/liquidity moves the caller's assets.
- `PolkadotXcm` — `transfer_assets`/`teleport_assets`/`send`/`execute` move assets off-chain.
- `Revive` — contract calls/instantiations carry a `value`.
- `Vesting::vested_transfer`, `Indices::transfer`/`force_transfer` — move balance/reserved deposit.

This is structurally identical to the PraisonAI root cause: a security gate implemented as an enumerated denylist (`_blocked_attrs`/`_blocked_calls` there, `!matches!(...)` here) that "fails open" whenever a new capability is added to the surrounding system (new builtin attribute vs. new pallet) without a corresponding denylist update. The westend prdoc explicitly names this as "fails open" behavior [6](#0-5) , confirming the maintainers recognize this exact failure mode as a real defect class — but the fix was not mirrored to `asset-hub-rococo`.

The entry point is a normal, unprivileged signed extrinsic: any account can call `pallet_proxy::add_proxy`/`create_pure` to grant another account a restricted `NonTransfer` delegation, believing (per the type's documented contract) that the delegate cannot move funds/assets. The delegate then calls `Proxy::proxy(origin, real, None, call)` with a `RuntimeCall::AssetConversion(...)`, `RuntimeCall::PolkadotXcm(...)`, `RuntimeCall::Revive(...)`, `RuntimeCall::ForeignAssets(...)`, `RuntimeCall::PoolAssets(...)`, `RuntimeCall::Vesting(vested_transfer{..})`, or `RuntimeCall::Indices(transfer{..})` on behalf of `real` — all of which pass the `NonTransfer` filter and dispatch successfully, moving the real account's assets. No governance, stolen keys, or privileged role is required; the "attacker" is simply the intentionally-lower-privileged `NonTransfer` delegate acting outside its documented capability.

### Impact Explanation
A delegate that was only ever meant to perform non-value-moving administration (identity, staking chill/validate, collator management, etc.) can fully drain or reallocate the delegator's fungible and non-fungible assets by routing through `AssetConversion` swaps, `PolkadotXcm` teleports/reserve-transfers to another chain, `Revive` contract calls carrying `value`, or the `ForeignAssets`/`PoolAssets` transfer families — none of which are blocked. This breaks the integrity guarantee of the `NonTransfer` proxy type and enables theft of the delegator's on-chain assets, matching the "Critical theft" category (unauthorized dispatch of value-moving calls under a trust boundary explicitly designed to prevent it).

### Likelihood Explanation
Reachability requires only that some account has granted (or the delegate has otherwise obtained, e.g. via a `create_pure` staking/algorithmic flow) a `NonTransfer` proxy — a documented, commonly-used, low-trust delegation type intended precisely to be safe for semi-trusted parties. Any holder of such a delegation can exploit this immediately with a single `Proxy::proxy` extrinsic; no race conditions, governance, or validator collusion are needed. The equivalent bug was independently found and patched for `asset-hub-westend` (PR 12771), demonstrating this is a realistic, previously-triggered defect pattern in this exact runtime family, not a hypothetical.

### Recommendation
Port the `asset-hub-westend` fix from `pr_12771.prdoc` to `asset-hub-rococo`: add `ForeignAssets`, `PoolAssets`, `AssetConversion`, `PolkadotXcm`, `Revive`, `Vesting::vested_transfer`, `Indices::transfer`, and `Indices::force_transfer` (and any other value-moving pallet/call added since the filter was last audited) to the `ProxyType::NonTransfer` deny-list in `cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs`. More durably, convert this and similar `InstanceFilter` implementations from deny-lists to allow-lists (as already done for the relay-chain `NonTransfer` filters in `polkadot/runtime/rococo/src/lib.rs` and `polkadot/runtime/westend/src/lib.rs`, which use `matches!` positively) so newly added pallets are excluded by default instead of automatically exposed.

### Proof of Concept
Exact reproduction was not executed (no filesystem/terminal access in this environment); the following is the concrete, minimal integration-test path derivable from the existing `pallet-proxy`/asset-hub test harness patterns already in the repo (e.g. `substrate/frame/proxy/src/tests.rs:318-379` `filtering_works`, and `asset-hub-westend/tests/tests.rs:2767-2866` which exercises the identical `Proxy::proxy` + `ProxyType` + `assert_last_event(ProxyExecuted...)` pattern for this runtime family):

1. In an `asset-hub-rococo` `ExtBuilder` test, fund `controller` and set up `Proxy::add_proxy(controller, delegate, ProxyType::NonTransfer, 0)`.
2. As `delegate`, call `Proxy::proxy(RuntimeOrigin::signed(delegate), controller, None, Box::new(RuntimeCall::AssetConversion(pallet_asset_conversion::Call::swap_exact_tokens_for_tokens { .. })))` (or `RuntimeCall::PolkadotXcm(pallet_xcm::Call::transfer_assets {..})`, or `RuntimeCall::Revive(pallet_revive::Call::call { value, .. })`).
3. Expected (per documented `NonTransfer` contract): `ProxyExecuted { result: Err(CallFiltered) }`.
4. Actual (per code at lines 608-616): the filter's `!matches!` only checks `Balances`/`Assets`/`NftFractionalization`/`Nfts`/`Uniques`, so the call is **not** filtered and dispatches, moving `controller`'s assets — `ProxyExecuted { result: Ok(()) }`.

Failed guard: `ProxyType::NonTransfer`'s `!matches!(...)` deny-list at `cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs:608-616`. Deployment evidence: the identical gap was found and closed for `asset-hub-westend` via `prdoc/pr_12771.prdoc`, confirming both the pallet set and the vulnerability class are real in this runtime family; `asset-hub-rococo`'s copy was not updated to match.

### Citations

**File:** cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs (L605-616)
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
			ProxyType::CancelProxy => matches!(
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

**File:** substrate/frame/proxy/src/lib.rs (L994-1023)
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
```
