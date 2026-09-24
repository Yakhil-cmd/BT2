### Title
`ProxyType::NonTransfer` on Asset Hub Rococo is a fails-open deny-list that omits `ForeignAssets`, `PoolAssets`, `AssetConversion`, `PolkadotXcm` and `Indices::transfer`/`force_transfer`, letting a restricted proxy move the delegator's funds - ([File: cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs])

### Summary
The CVE describes Apache MINA SSHD accepting an OpenSSH certificate without checking for embedded restriction options (`force-command`, `verify-required`): the credential is documented/intended as restricted, but the validator never checks the options that should constrain it, so the holder can act outside the intended restriction. The Polkadot SDK analog is `pallet_proxy::InstanceFilter` for `ProxyType::NonTransfer` on Asset Hub Rococo: it is documented ("Can execute any call that does not transfer funds or assets") and is implemented as a *deny*-list, so any `RuntimeCall` variant not explicitly named is implicitly permitted. Several fund/asset-moving pallets that exist in this same runtime (`ForeignAssets`, `PoolAssets`, `AssetConversion`, `PolkadotXcm`, and `Indices::transfer`/`force_transfer`) are not in the deny-list, so a delegate holding only the restricted `NonTransfer` permission can still move the delegator's assets — exactly mirroring "restriction option present but not validated, so the restricted operation still succeeds."

### Finding Description
`ProxyType::NonTransfer::filter` is defined at [1](#0-0)  as:
```
ProxyType::NonTransfer => !matches!(
    c,
    RuntimeCall::Balances { .. } |
        RuntimeCall::Assets { .. } |
        RuntimeCall::NftFractionalization { .. } |
        RuntimeCall::Nfts { .. } |
        RuntimeCall::Uniques { .. }
),
```
This is the exact same fail-open pattern that was identified and fixed for `asset-hub-westend` in [2](#0-1) , which documents:

> "the `ProxyType::NonTransfer` call filter is a deny-list and so fails open: any pallet added to the runtime is reachable by a `NonTransfer` proxy unless it is listed explicitly... `ForeignAssets` and `PoolAssets`... `AssetConversion`... `PolkadotXcm`... `Indices::transfer` and `Indices::force_transfer`..."

That fix (and the companion superset fix in [3](#0-2) ) was applied to `asset-hub-westend-runtime` only, as confirmed by the corrected filter at [4](#0-3) , which explicitly denies `ForeignAssets`, `PoolAssets`, `AssetConversion`, `Psm`, `PolkadotXcm`, `Revive`, and `Indices::transfer`/`force_transfer`. The `asset-hub-rococo` copy of the same code, at [5](#0-4) , was never patched, and the runtime does declare a `ForeignAssets`/`PoolAssets`/`AssetConversion`/`PolkadotXcm` construct (117 references to these names in the file), so the missing entries are reachable, live `RuntimeCall` variants, not dead code.

The dispatch path that trusts this filter is `pallet_proxy::do_proxy`, at [6](#0-5) : the origin filter for a delegated call is `def.proxy_type.filter(c)`, i.e. it relies entirely on `InstanceFilter::filter` to reject anything the proxy type should not be able to do. Because the filter fails open, `pallet_proxy` will dispatch `ForeignAssets::transfer`, `PoolAssets::transfer`, `AssetConversion::swap_exact_tokens_for_tokens`/liquidity withdrawal, `PolkadotXcm::transfer_assets`/`teleport_assets`, and `Indices::transfer`/`force_transfer` on behalf of the delegator even though the delegator only authorized a `NonTransfer` proxy.

### Impact Explanation
A delegator who grants a `ProxyType::NonTransfer` proxy — believing, per the documented semantics, that the delegate cannot move funds or assets — is actually exposed to the delegate moving funds via `ForeignAssets`, `PoolAssets`, swaps/liquidity via `AssetConversion`, and cross-chain asset moves via `PolkadotXcm::transfer_assets`/`teleport_assets`, as well as recovering the delegator's `Indices` deposit via `transfer`/`force_transfer`. This breaks the authorization boundary the delegator explicitly set, i.e. unauthorized asset movement by a nominally restricted delegate — a direct integrity/theft-class issue, analogous to the SSH certificate holder executing commands the certificate's embedded restriction was meant to forbid.

### Likelihood Explanation
The attacker only needs to be a delegate under an existing `ProxyType::NonTransfer` proxy relationship (a normal, permitted relay/collator-agnostic user flow granted via `pallet_proxy::add_proxy`, no privileged role or governance required) and to submit an ordinary signed `Proxy::proxy` extrinsic wrapping `ForeignAssets`/`PoolAssets`/`AssetConversion`/`PolkadotXcm`/`Indices` calls. This requires no forged proof, no validator/collator collusion, and no unusual pre-state — only that the delegator has granted a `NonTransfer` proxy, which is the documented "safe" grant for this exact purpose.

However, this affects `asset-hub-rococo`, and the codebase's own history notes that Rococo has repeatedly been treated by Parity as the deprecated/superseded testnet in favor of Westend (see [7](#0-6)  "Since Rococo is now deprecated..."), and `cumulus/README.md` lists Paseo/Westend, not Rococo, as the current maintained testnets [8](#0-7) . I was not able to fully confirm from the index whether `asset-hub-rococo` is presently enrolled in a *live* Parity bug-bounty program scope as opposed to being a legacy/decommissioned testnet; this materially affects bounty eligibility per the report's own criteria ("Verify the matching live Parity/Snowbridge program and affected version"). Because a live-network/live-program confirmation could not be completed with the tools available, I flag this explicitly as unresolved rather than asserting eligibility.

### Recommendation
Port the fix from `pr_12771`/`pr_12769` (already applied to `asset-hub-westend-runtime`) to `asset-hub-rococo-runtime`: add `ForeignAssets`, `PoolAssets`, `AssetConversion`, `PolkadotXcm`, and `Indices::transfer`/`Indices::force_transfer` to the `ProxyType::NonTransfer` deny-list at [9](#0-8) , and audit all other runtimes sharing this pattern (e.g. `substrate/frame/staking-async/runtimes/parachain/src/lib.rs`, seen at lines 672-682 with the identical narrower list) for the same omissions. Longer term, convert deny-list `InstanceFilter` implementations to allow-lists, or add an exhaustiveness test per runtime (as already exists for `asset-hub-westend` in `tests/tests.rs`, `non_transfer_proxy_rejects_value_moving_calls`) so newly-added pallets cannot silently slip through `NonTransfer`.

### Proof of Concept
No PoC was executed. I did not run a local Rust/FRAME integration test; this report is a static-analysis analog derived from comparing `asset-hub-rococo`'s `ProxyType::NonTransfer::filter` (lines 605-616) against the already-fixed `asset-hub-westend` version and the corresponding regression test `non_transfer_proxy_rejects_value_moving_calls` (`cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs:2642-2668`), which enumerates the exact call families ("value_moving_calls") that leak through the deny-list pattern. A concrete reproduction would instantiate `asset-hub-rococo-runtime`, call `Proxy::add_proxy(delegator, delegate, ProxyType::NonTransfer, 0)`, then have the delegate call `Proxy::proxy(delegate, delegator, None, Box::new(RuntimeCall::ForeignAssets(pallet_assets::Call::transfer{..})))` (or `PoolAssets`/`AssetConversion`/`PolkadotXcm::transfer_assets`/`Indices::transfer`) and assert it dispatches successfully rather than being `CallFiltered` — this was not executed against a live network or test harness in this pass. Eligibility further depends on confirming asset-hub-rococo's current status in Parity's live bounty program, which I could not verify from the indexed files alone.

### Citations

**File:** cumulus/parachains/runtimes/assets/asset-hub-rococo/src/lib.rs (L582-616)
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
			ProxyType::CancelProxy => matches!(
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

**File:** prdoc/pr_12769.prdoc (L1-18)
```text
title: 'asset-hub-westend: fix `NonTransfer` proxy falsely claiming `Governance` containment'
doc:
- audience: Runtime User
  description: |-
    On Asset Hub Westend, the `NonTransfer` proxy type declared itself a superset of the
    `Governance` proxy type while its call filter denied the `Treasury`, `ConvictionVoting`,
    `Referenda` and `Whitelist` calls that `Governance` admits.

    Because `pallet_proxy` authorizes `add_proxy`/`remove_proxy` through `is_superset`, a
    `NonTransfer` proxy could add a `Governance` proxy for its delegator and thereby reach calls
    that its own filter denies. `NonTransfer` no longer declares `Governance` as a subset, so this
    is rejected.

    Existing `Governance` proxies are unaffected; only the ability of a `NonTransfer` proxy to
    create or remove one changes. The `Collator`, `Staking`, `NominationPools` and
    `StakingOperator` subsets of `NonTransfer` are unchanged.
crates:
- name: asset-hub-westend-runtime
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/lib.rs (L829-860)
```rust
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

**File:** prdoc/1.16.0/pr_5074.prdoc (L1-7)
```text
title: "Snowbridge on Westend"

doc:
  - audience: Runtime Dev
    description: |
      Since Rococo is now deprecated, we need another testnet to detect bleeding-edge changes 
      to Substrate, Polkadot, BEEFY consensus protocols that could brick the bridge.
```

**File:** cumulus/README.md (L191-209)
```markdown
## Testnets

### Paseo

[Paseo](https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Fpaseo.rpc.amforc.com#/explorer) is the newest testnet for Polkadot,
replacing Rococo as a decentralised, community run, stable testnet for Parachain teams and dapp developers to build on.
For more information, check the [Paseo repo](https://github.com/paseo-network).

### Westend

[Westend](https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Fwestend-rpc.polkadot.io#/explorer)
is a long running testnet for Polkadot,
primarily intended to provide a testing environment for Parity to test the latest changes in the SDK.

### Testnet Parachains

A few testnet parachain instances:

- [Asset Hub Westend](https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Fwestend-asset-hub-rpc.polkadot.io#/explorer)
```
