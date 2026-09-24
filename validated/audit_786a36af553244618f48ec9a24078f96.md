Confirmed: `ForeignAssets`, `PoolAssets`, `AssetConversion`, `Revive`, `Treasury`, `Scheduler`, `PolkadotXcm`, `ConvictionVoting`, `Referenda`, and `Whitelist` pallets all exist in the `asset-hub-rococo` runtime construct, yet none of them are denied by `ProxyType::NonTransfer`'s filter there.

### Title
`ProxyType::NonTransfer` on Asset Hub Rococo fails to deny value-moving pallets (`ForeignAssets`, `PoolAssets`, `AssetConversion`, `PolkadotXcm`, `Revive`, `Treasury`, governance) - ([File: cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs])

### Summary
`pallet-proxy`'s `InstanceFilter` for `ProxyType::NonTransfer` on `asset-hub-rococo` is implemented as a deny-list that only excludes `Balances`, `Assets`, `NftFractionalization`, `Nfts`, and `Uniques`. Every other pallet in the runtime, including several that move the delegator's funds/assets or dispatch privileged operations on their behalf, is implicitly *allowed*. The comment/documented intent ("Can execute any call that does not transfer funds or assets") is therefore violated for `ForeignAssets`, `PoolAssets`, `AssetConversion`, `PolkadotXcm`, `pallet-revive` (contracts with `value`), `Treasury`, `Scheduler`, `ConvictionVoting`, `Referenda`, and `Whitelist`. [1](#0-0) 

### Finding Description
`pallet-proxy` lets an account (`real`) authorize a `delegate` to dispatch calls on its behalf, restricted by `T::ProxyType::filter`. A delegate granted the `NonTransfer` proxy type is meant to be limited to calls that cannot move the delegator's funds/assets, per the type's own doc comment: "Can execute any call that does not transfer funds or assets". [2](#0-1) 

The filter is implemented as a deny-list (`!matches!(c, ...)`), so any pallet call *not* explicitly named is admitted by default — the check fails open. On `asset-hub-rococo` the deny-list only names `Balances`, `Assets`, `NftFractionalization`, `Nfts`, `Uniques`: [3](#0-2) 

The runtime, however, also includes `ForeignAssets` and `PoolAssets` (other `pallet-assets` instances that transfer value exactly like `Assets`), `AssetConversion` (swaps/liquidity that move the caller's assets), `PolkadotXcm` (`transfer_assets`/`teleport_assets`/raw `execute`/`send` that move assets off-chain), `pallet-revive` (contract calls/instantiations carrying a `value` transfer), `Treasury`, `Scheduler`, `ConvictionVoting`, `Referenda`, and `Whitelist` — none of which appear in the deny-list, so they are all reachable through a `NonTransfer` proxy. This is exactly the bug class that was already identified and fixed for the sibling `asset-hub-westend` runtime (which now explicitly denies `ForeignAssets`, `PoolAssets`, `AssetConversion`, `Revive`, `PolkadotXcm`, `Scheduler`, `Treasury`, `ConvictionVoting`, `Referenda`, `Whitelist`) and for the `staking-async` parachain runtime via `prdoc/pr_12922.prdoc` ("deny ForeignAssets and PoolAssets transfers to the NonTransfer proxy"). [4](#0-3) [5](#0-4) 

This maps to the MariaDB bug class: EXECUTE-equivalent access granted through a role-like mechanism (a `NonTransfer` proxy grant, itself typically obtained with the intent of *limited* delegation) inadvertently exposes/enables a strictly more privileged operation (moving funds/assets, or calling governance/treasury) that the grantor never explicitly authorized and that the type's own filter is supposed to withhold — an authorization check that is logically incomplete for the actual set of protected resources.

### Impact Explanation
A `real` account that grants `ProxyType::NonTransfer` to a `delegate` — believing (per the documented semantics) that the delegate cannot move funds or assets — is actually exposing itself to: unauthorized `ForeignAssets`/`PoolAssets` transfers, `AssetConversion` swaps that drain balances into another asset, `PolkadotXcm` teleports/reserve-transfers that move assets off-chain (potentially irrecoverably to a chain-controlled account), `pallet-revive` contract calls carrying arbitrary `value`, and `Treasury`/governance dispatch. This is a direct authorization-bypass leading to potential theft/loss of the delegator's assets, which is the closest on-chain analog of the MariaDB issue's "unauthorized capability exposed via a coarser role grant."

### Likelihood Explanation
Requires no privileged prerequisite beyond the delegator's own (routine, low-trust) decision to grant a `NonTransfer` proxy — a common intended-to-be-safe operation. The delegate is an ordinary signed account with no special role, matching the "no privileged prerequisite" requirement. However, exploitability depends on the delegator actually granting `NonTransfer` on `asset-hub-rococo` specifically (a test/community network); I could not verify from the index whether this runtime is still actively deployed/live or superseded, which affects real-world severity/bounty eligibility.

### Recommendation
Align `asset-hub-rococo`'s `ProxyType::NonTransfer` filter with the fixed `asset-hub-westend` version: explicitly deny `ForeignAssets`, `PoolAssets`, `AssetConversion`, `PolkadotXcm`, `Revive`, `Scheduler`, `Treasury`, `ConvictionVoting`, `Referenda`, and `Whitelist` (or, better, refactor to an allow-list so newly added pallets don't silently become reachable by default).

### Proof of Concept
I was not able to execute a live reproduction in this environment (read-only ask mode, no compiler/test runner access). The evidence is a direct code-diff comparison: `asset-hub-westend`'s `NonTransfer` filter explicitly denies `ForeignAssets`, `PoolAssets`, `AssetConversion`, `Revive`, `PolkadotXcm`, `Scheduler`, `Treasury`, `ConvictionVoting`, `Referenda`, `Whitelist` [4](#0-3) , while `asset-hub-rococo`'s equivalent filter only denies `Balances`, `Assets`, `NftFractionalization`, `Nfts`, `Uniques` [3](#0-2) , despite both runtimes including the same set of value-moving pallets (confirmed present via `ForeignAssets`/`PoolAssets`/`AssetConversion`/`Revive`/`Treasury`/`Scheduler`/`PolkadotXcm`/`ConvictionVoting`/`Referenda`/`Whitelist` matches in `asset-hub-rococo/src/lib.rs`). A minimal integration test analogous to the existing westend regression test `non_transfer_proxy_is_not_a_superset_of_governance`/`proxy_type_superset_relation_matches_call_filters` [6](#0-5)  — asserting `!ProxyType::NonTransfer.filter(&RuntimeCall::ForeignAssets(...))` etc. — would fail on `asset-hub-rococo` today since no such test or deny entry exists there. I did not run this test; this is a static code-diff finding, not an executed PoC.

### Citations

**File:** cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs (L583-615)
```rust
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
impl Default for ProxyType {
	fn default() -> Self {
		Self::Any
	}
}

impl InstanceFilter<RuntimeCall> for ProxyType {
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

**File:** prdoc/pr_12922.prdoc (L1-12)
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
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L2494-2542)
```rust
fn proxy_type_superset_relation_matches_call_filters() {
	use frame_support::traits::InstanceFilter;

	let calls = representative_proxy_calls();

	for superset in all_proxy_types() {
		for subset in all_proxy_types() {
			if !superset.is_superset(&subset) {
				continue;
			}

			for call in calls.iter() {
				if subset.filter(call) {
					assert!(
						superset.filter(call),
						"lattice violated: {superset:?} declares itself a superset of {subset:?}, \
						 but rejects {call:?} which {subset:?} admits",
					);
				}
			}
		}
	}
}

/// Regression test for <https://github.com/paritytech/polkadot-sdk/issues/12724>.
///
/// `NonTransfer` used to claim `Governance` as a subset while denying the `Treasury`,
/// `ConvictionVoting`, `Referenda` and `Whitelist` calls that `Governance` admits, which let a
/// `NonTransfer` proxy add a `Governance` proxy and widen its own permissions.
#[test]
fn non_transfer_proxy_is_not_a_superset_of_governance() {
	use asset_hub_westend_runtime::ProxyType;
	use frame_support::traits::InstanceFilter;

	// `NonTransfer` denies every governance call family that `Governance` admits, except `Utility`.
	for call in [
		RuntimeCall::Treasury(pallet_treasury::Call::void_spend { index: 0 }),
		RuntimeCall::ConvictionVoting(pallet_conviction_voting::Call::remove_vote {
			class: None,
			index: 0,
		}),
		RuntimeCall::Referenda(pallet_referenda::Call::refund_decision_deposit { index: 0 }),
		RuntimeCall::Whitelist(pallet_whitelist::Call::remove_whitelisted_call {
			call_hash: Default::default(),
		}),
	] {
		assert!(ProxyType::Governance.filter(&call), "Governance must admit {call:?}");
		assert!(!ProxyType::NonTransfer.filter(&call), "NonTransfer must deny {call:?}");
	}
```
