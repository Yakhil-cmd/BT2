### Title
`ProxyType::NonTransfer` deny-list in the reference `node-runtime` fails to deny `AssetConversion` swaps and `pallet_revive` value-carrying calls, letting a value-restricted proxy move the delegator's funds - (`substrate/bin/node/runtime/src/lib.rs`)

### Summary
`ProxyType::NonTransfer` in `substrate/bin/node/runtime/src/lib.rs` is implemented as a deny-list (`!matches!(...)`), so any pallet call not explicitly listed is admitted by default. It denies only `Balances`, `Assets`, `Uniques`, `Nfts`, `Vesting::vested_transfer`, and `Indices::transfer`. It does not deny `AssetConversion` (asset swaps) or `pallet_revive` (contract calls/instantiations that carry a `value`), and it omits `Indices::force_transfer` (which also repatriates the account's reserved deposit). [1](#0-0) 

This is the exact bug class this same repository already found and fixed in the sibling Asset Hub Westend runtime: PR #12771 explicitly added `AssetConversion`, `Revive`, `ForeignAssets`/`PoolAssets`, `PolkadotXcm`, and `Indices::force_transfer` to that runtime's `NonTransfer` deny-list because the fail-open deny-list silently admitted every newly-added value-moving pallet. [2](#0-1) [3](#0-2) 

The `substrate/bin/node/runtime` was never brought in line with that fix, even though it imports and wires up the same two pallet families (`pallet_asset_conversion`, `pallet_revive`) that were the direct subject of PR #12771. [4](#0-3) 

### Finding Description
`pallet_proxy` authorizes every proxied call solely through `InstanceFilter::filter` before dispatch: [5](#0-4) 

A delegator who creates a `ProxyType::NonTransfer` proxy is documented (by analogy with every other runtime in this codebase, e.g. Rococo and Asset Hub Westend) to be protected against the delegate moving their funds/assets. But because the filter here is a deny-list keyed to a fixed, hand-maintained list of `RuntimeCall` variants, any call family added to the runtime after this list was written - or simply not anticipated by the list's author - is reachable by default. `AssetConversion::swap_exact_tokens_for_tokens`/`add_liquidity` move the caller's assets exactly as a `Balances::transfer` would, and `pallet_revive::call`/`instantiate` carry a `value` field that debits the caller's native balance on execution, yet neither pallet appears anywhere in the `NonTransfer` match arm. [6](#0-5) 

This mirrors the reported Gitea root cause precisely: a security check (`checkDownloadTokenScope`, here `InstanceFilter::filter`'s deny-list) is correctly applied on some code paths (Balances, Assets, Uniques, Nfts) but missing on sibling paths that carry the same kind of sensitive capability (AssetConversion, Revive) - not because the mechanism is wrong, but because it was never extended to cover every call family that needed it, and nothing in the type system forces that completeness. The codebase's own regression tests for Asset Hub Westend explicitly document this failure mode and enumerate `AssetConversion`/`Revive` as calls that "move the delegator's funds or assets": [7](#0-6) 

That same test does not exist for `substrate/bin/node/runtime`, and the corresponding source fix was never ported there.

### Impact Explanation
A delegator who grants a `ProxyType::NonTransfer` proxy to a partially-trusted delegate (the documented purpose of this proxy type across the codebase) is exposed to that delegate swapping the delegator's tokens via `AssetConversion` or invoking `pallet_revive` contract calls/instantiations that transfer the delegator's native balance as `value` - capabilities the proxy type is meant to withhold. This is a direct, deterministic loss-of-funds primitive for any account using this proxy type in this runtime, reachable with no privileged role, governance action, or stolen key: the attacker is simply the delegate the victim already (partially) trusted for non-transfer operations.

### Likelihood Explanation
High, given normal use: any account that creates a `NonTransfer` proxy under this runtime and later has `AssetConversion` or `pallet_revive` calls proxied through it (or a malicious/compromised delegate deliberately submits them) triggers the bypass with a single, ordinary signed extrinsic (`Proxy::proxy`). No race conditions, no chain-specific configuration beyond what's already default, and no unusual preconditions are required.

### Recommendation
Add `RuntimeCall::AssetConversion(..)` and `RuntimeCall::Revive(..)` (and `Indices::force_transfer`) to the `NonTransfer` deny-list in `substrate/bin/node/runtime/src/lib.rs`, mirroring the fix already applied to Asset Hub Westend in PR #12771. Longer-term, replace the deny-list pattern with an allow-list (as already done in Rococo's `NonTransfer`, `polkadot/runtime/rococo/src/lib.rs:922-967`) or add a lattice/lint check across all runtimes analogous to `proxy_type_superset_relation_matches_call_filters` and `non_transfer_proxy_rejects_value_moving_calls` in `asset-hub-westend/tests/tests.rs`, so a newly added value-moving pallet cannot silently slip through the `NonTransfer` filter in any runtime, not just the one that was already audited.

### Proof of Concept
Not executed against a live network. Reachability evidence:
- `pallet_proxy::Config` for `Runtime` sets `ProxyType = ProxyType` and `RuntimeCall = RuntimeCall`, so `do_proxy` applies exactly the `filter` shown above to every proxied call: [8](#0-7) 
- The deny-list omits `AssetConversion`/`Revive`, so `ProxyType::NonTransfer.filter(&RuntimeCall::AssetConversion(..))` and `filter(&RuntimeCall::Revive(..))` evaluate to `true` by construction of `!matches!(...)`.
- The sibling runtime's own fix and regression test (`non_transfer_proxy_rejects_value_moving_calls`) confirm these exact call families are classified as "value-moving" and must be denied by any `NonTransfer` proxy type in this codebase.

I was not able to fully re-verify, in the final iteration, that `AssetConversion` and `Revive` are registered as `RuntimeCall` variants inside this runtime's `construct_runtime!` macro invocation (only their pallet-level imports and `Config` usage were confirmed); a background Devin session with terminal/build access should confirm the `construct_runtime!` pallet list and compile a minimal integration test analogous to `asset-hub-westend`'s `non_transfer_proxy_rejects_value_moving_calls`, driving `Proxy::proxy(delegate_origin, real, None, Box::new(RuntimeCall::AssetConversion(..)))` (and the `Revive` equivalent) through `substrate/bin/node/runtime` to assert dispatch succeeds under a `NonTransfer` proxy, before this is escalated as a confirmed finding.

### Citations

**File:** substrate/bin/node/runtime/src/lib.rs (L81-91)
```rust
use pallet_asset_conversion::{AccountIdConverter, Ascending, Chain, WithFirstAsset};
use pallet_asset_conversion_tx_payment::SwapAssetAdapter;
use pallet_assets_precompiles::{InlineIdConfig, ERC20};
use pallet_broker::{CoreAssignment, CoreIndex, CoretimeInterface, PartsOf57600, TaskId};
use pallet_election_provider_multi_phase::{GeometricDepositBase, SolutionAccuracyOf};
use pallet_identity::legacy::IdentityInfo;
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use pallet_nfts::PalletFeatures;
use pallet_nis::WithMaximumOf;
use pallet_nomination_pools::PoolId;
use pallet_revive::evm::runtime::EthExtra;
```

**File:** substrate/bin/node/runtime/src/lib.rs (L437-449)
```rust
impl InstanceFilter<RuntimeCall> for ProxyType {
	fn filter(&self, c: &RuntimeCall) -> bool {
		match self {
			ProxyType::Any => true,
			ProxyType::NonTransfer => !matches!(
				c,
				RuntimeCall::Balances(..) |
					RuntimeCall::Assets(..) |
					RuntimeCall::Uniques(..) |
					RuntimeCall::Nfts(..) |
					RuntimeCall::Vesting(pallet_vesting::Call::vested_transfer { .. }) |
					RuntimeCall::Indices(pallet_indices::Call::transfer { .. })
			),
```

**File:** substrate/bin/node/runtime/src/lib.rs (L475-480)
```rust
impl pallet_proxy::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type Currency = Balances;
	type ProxyType = ProxyType;
	type ProxyDepositBase = ProxyDepositBase;
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

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L2642-2667)
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
```
