## Analysis

The OpenFGA bug's invariant is: an authorization filter that is supposed to restrict a permission (tupleset relation) silently admits cases its author never enumerated (a wildcard slipping past an allow/deny check). In the Polkadot SDK, `pallet_proxy`'s `InstanceFilter` plays the same authorization-gate role: a delegator restricts a delegate to a `ProxyType`, and the pallet trusts the runtime's `filter(&self, call) -> bool` implementation to reject everything outside the declared scope.

`asset-hub-rococo`'s `ProxyType::NonTransfer` implements this as a **deny-list**, which structurally "fails open" — any call variant not explicitly named is *admitted*: [1](#0-0) 

This list only denies `Balances`, `Assets`, `NftFractionalization`, `Nfts`, `Uniques`. But the same runtime configures `ForeignAssets`, `PoolAssets`, `AssetConversion`, and `PolkadotXcm` (117 references to these identifiers exist in that file), none of which appear in the deny-list, so a `NonTransfer` proxy on this chain can still call `ForeignAssets::transfer`, `PoolAssets::transfer`, `AssetConversion::swap_exact_tokens_for_tokens`, and `PolkadotXcm::transfer_assets`/`send`/`execute` on the delegator's behalf.

This is not speculative: the exact same bug class was already found and fixed elsewhere in this same codebase snapshot:
- `asset-hub-westend`'s `NonTransfer` filter was patched to add `ForeignAssets`, `PoolAssets`, `AssetConversion`, `Psm`, `PolkadotXcm`, `Revive`, `Vesting::vested_transfer`, `Indices::transfer`/`force_transfer`, with an explicit code comment "this is a deny-list, so it fails open": [2](#0-1) , documented in [3](#0-2) , and covered by a regression test: [4](#0-3) 
- `staking-async` parachain runtime got an analogous fix for `ForeignAssets`/`PoolAssets`, documented in [5](#0-4)  with its own regression test at [6](#0-5) 

`asset-hub-rococo` received neither the deny-list expansion nor a regression test (`grep_search` for `non_transfer_proxy|value_moving_calls` in that runtime's directory returned no matches). I was not able to fully verify every `RuntimeCall` variant name in `asset-hub-rococo` (e.g., whether it names its contracts pallet `Revive` or `Contracts`, or whether a `Psm` pallet is present there) — this would need to be confirmed against that runtime's actual pallet configuration in `construct_runtime!` before a fix is written; I recommend a Devin session enumerate that exactly.

### Title
`ProxyType::NonTransfer` deny-list fails open on Asset Hub Rococo, admitting asset/XCM transfers - (File: `cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs`)

### Summary
`asset-hub-rococo`'s `InstanceFilter<RuntimeCall> for ProxyType` implements `NonTransfer` as a deny-list that only names `Balances`, `Assets`, `NftFractionalization`, `Nfts`, `Uniques`. Calls to `ForeignAssets`, `PoolAssets`, `AssetConversion`, and `PolkadotXcm` — all of which move the delegator's funds/assets — are not in the list and are therefore admitted, contradicting the type's documented purpose ("Can execute any call that does not transfer funds or assets": [7](#0-6) ). This is the same authorization-bypass bug class as CVE-2022-39341 (an allow/deny check silently admitting cases outside its author's intended enumeration), already identified and fixed for `asset-hub-westend` and `staking-async-parachain` in this codebase, but not for `asset-hub-rococo`.

### Finding Description
`pallet_proxy::Proxy::proxy` dispatches the inner call as the delegator's origin only if `ProxyType::filter(call)` returns `true` for the proxy relationship's declared type. `NonTransfer::filter` on `asset-hub-rococo` is a negated `matches!` (deny-list): `!matches!(c, Balances|Assets|NftFractionalization|Nfts|Uniques)`. Any `RuntimeCall` variant not named in that pattern returns `true` (permitted), regardless of whether it moves value. Since the runtime configures `ForeignAssets`, `PoolAssets`, `AssetConversion`, and `PolkadotXcm` pallets (each capable of moving the delegator's funds to a third party), a delegate holding only a `NonTransfer` proxy can dispatch e.g. `ForeignAssets::transfer`, `PoolAssets::transfer`, `AssetConversion::swap_exact_tokens_for_tokens`, or `PolkadotXcm::transfer_assets` as the delegator, exceeding the authorization the delegator granted.

### Impact Explanation
A delegator who grants a `NonTransfer` proxy — expecting the delegate cannot move their funds/assets — is exposed to fund/asset loss through pallets the deny-list forgot to enumerate. This matches the sibling fix's own severity assessment (patch-level runtime fix, no root/governance needed) and mirrors the Medium severity of the OpenFGA analog (authorization bypass, no privileged prerequisite beyond the normal, permitted `add_proxy`/`proxy` extrinsics).

### Likelihood Explanation
Granting `NonTransfer` proxies to semi-trusted delegates (bots, dApp frontends, custodial-lite services) is a standard, encouraged usage pattern precisely because it is documented as safe for "does not transfer funds or assets." No governance, root, or privileged role is needed — only the ordinary `pallet_proxy::add_proxy` and `pallet_proxy::proxy` extrinsics that any signed account can call.

### Recommendation
Port the same fix already applied to `asset-hub-westend` (PR #12771) and `staking-async-parachain` (PR #12922) to `asset-hub-rococo`: extend the `NonTransfer` deny-list to also reject `ForeignAssets`, `PoolAssets`, `AssetConversion`, and `PolkadotXcm` (and any other value-moving pallet present in that runtime's actual `construct_runtime!`, e.g. a contracts pallet if configured), and add the equivalent regression test (`non_transfer_proxy_rejects_value_moving_calls`) to prevent recurrence.

### Proof of Concept
Not executed. A concrete reproduction (to be run by a background agent with the full repo/toolchain) would mirror the existing westend regression test but targeting `asset_hub_rococo_runtime::ProxyType`:
```rust
use asset_hub_rococo_runtime::{ProxyType, RuntimeCall};
use frame_support::traits::InstanceFilter;

let call = RuntimeCall::ForeignAssets(pallet_assets::Call::<Runtime, ForeignAssetsInstance>::transfer {
    id: some_asset_location(), target: BOB.into(), amount: 1,
});
assert!(!ProxyType::NonTransfer.filter(&call)); // EXPECTED false, ACTUAL true (bug: not denied)
```
Given the deny-list at [8](#0-7)  does not mention `ForeignAssets`, `PoolAssets`, `AssetConversion`, or `PolkadotXcm`, this assertion is expected to fail (i.e., `filter` returns `true`, admitting the value-moving call) based on static analysis; I did not compile/run this against the actual crate, and the exact set of value-moving pallets present in `asset-hub-rococo`'s `construct_runtime!` should be re-verified before filing/fixing.

### Citations

**File:** cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs (L582-597)
```rust
pub enum ProxyType {
	/// Fully permissioned proxy. Can execute any call on behalf of _proxied_.
	Any,
	/// Can execute any call that does not transfer funds or assets.
	NonTransfer,
	/// Proxy with the ability to reject time-delay proxy announcements.
	CancelProxy,
	/// Assets proxy. Can execute any call from `assets`, **including asset transfers**.
	Assets,
	/// Owner proxy. Can execute calls related to asset ownership.
	AssetOwner,
	/// Asset manager. Can execute calls related to asset management.
	AssetManager,
	/// Collator selection proxy. Can execute calls related to collator selection mechanism.
	Collator,
}
```

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

**File:** prdoc/pr_12922.prdoc (L1-15)
```text
title: 'staking-async parachain: deny ForeignAssets and PoolAssets transfers to the `NonTransfer` proxy'
doc:
- audience: Runtime User
  description: |-
    In the `staking-async` parachain runtime, the `ProxyType::NonTransfer` call filter is a
    deny-list and so fails open: any pallet added to the runtime is reachable by a `NonTransfer`
    proxy unless it is listed explicitly. The deny-list named only `Assets` (the TrustBackedAssets
    instance) and omitted the other `pallet-assets` instances, contradicting the documented policy
    that this proxy type can only execute calls that do not transfer funds or assets.

    `ForeignAssets` and `PoolAssets`, which transfer value exactly as `Assets` does, are now
    denied to a `NonTransfer` proxy.
crates:
- name: pallet-staking-async-parachain-runtime
  bump: patch
```

**File:** substrate/frame/staking-async/runtimes/parachain/src/lib.rs (L2350-2379)
```rust
#[test]
fn non_transfer_proxy_denies_other_asset_instances() {
	use frame_support::traits::InstanceFilter;

	// `ForeignAssets` (Instance2) and `PoolAssets` (Instance3) move fungibles just like
	// `Assets` (Instance1) does, so a `NonTransfer` proxy must not be able to call them.
	let foreign_assets_transfer = RuntimeCall::ForeignAssets(pallet_assets::Call::<
		Runtime,
		ForeignAssetsInstance,
	>::transfer {
		id: xcm::v5::Location::parent(),
		target: sp_runtime::MultiAddress::Id(AccountId::from([0u8; 32])),
		amount: 1,
	});
	assert!(
		!ProxyType::NonTransfer.filter(&foreign_assets_transfer),
		"NonTransfer must deny ForeignAssets transfers",
	);

	let pool_assets_transfer =
		RuntimeCall::PoolAssets(pallet_assets::Call::<Runtime, PoolAssetsInstance>::transfer {
			id: 1,
			target: sp_runtime::MultiAddress::Id(AccountId::from([0u8; 32])),
			amount: 1,
		});
	assert!(
		!ProxyType::NonTransfer.filter(&pool_assets_transfer),
		"NonTransfer must deny PoolAssets transfers",
	);
}
```
