### Title
`SafeCallFilter = AllExceptReapStash` only screens the top-level `Transact` call, allowing `Staking::reap_stash` to reach dispatch when wrapped in `Utility::batch` (or similar composite dispatch) - (File: system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs)

### Summary
`XcmConfig::SafeCallFilter` is set to `AllExceptReapStash` [1](#0-0)  and origin conversion for `Transact` includes `SovereignSignedViaLocation<LocationToAccountId, RuntimeOrigin>` [2](#0-1) , meaning any sibling parachain's sovereign account gets a normal `Signed` origin for dispatch. The `xcm-executor`'s `SafeCallFilter` check is architecturally a single, non-recursive check performed on the outer `RuntimeCall` supplied to the `Transact` instruction; it is not re-applied to inner calls unpacked and re-dispatched by composite pallets such as `pallet_utility::batch`, `pallet_utility::batch_all`, or `pallet_proxy::proxy`. If `AllExceptReapStash` is implemented as a simple pattern match against the `Staking::reap_stash` variant of the outer call (the conventional, minimal implementation of this kind of filter, and the only source I was able to correlate to its name/usage), wrapping the call as `RuntimeCall::Utility(Call::batch { calls: vec![RuntimeCall::Staking(Call::reap_stash{..})] })` presents a different top-level variant to `SafeCallFilter::contains`, which would return `true`. The nested `reap_stash` call would then only be gated by `frame_system::Config::BaseCallFilter` during `pallet_utility`'s internal `call.dispatch(origin)`, which is a separate config item from `SafeCallFilter` and typically permissive (`Everything`) on system parachains.

### Finding Description
- Entry path: XCMP `Transact` from a sibling parachain's sovereign account → `XcmOriginToTransactDispatchOrigin` resolves the origin via `SovereignSignedViaLocation<LocationToAccountId, RuntimeOrigin>` into a normal `Signed(AccountId)` origin [2](#0-1) .
- `xcm_executor::Config::SafeCallFilter` for Asset Hub Polkadot is `AllExceptReapStash` [1](#0-0) . This type is intended to specifically block direct dispatch of `pallet_staking::Call::reap_stash` through XCM `Transact`, distinct from the general `BaseCallFilter` used for locally-submitted extrinsics.
- The `xcm-executor`'s handling of the `Transact` instruction invokes `SafeCallFilter::contains(&call)` exactly once against the *outer* call decoded from the XCM message, before dispatching it. It does not recursively inspect calls nested inside composite/proxy pallets.
- If an attacker (any sibling parachain able to send XCMP, or any location able to reach a `Transact` with a Signed-convertible origin) encodes the call as `RuntimeCall::Utility(pallet_utility::Call::batch { calls: vec![RuntimeCall::Staking(pallet_staking::Call::reap_stash { stash, num_slashing_spans })] })`, the outer call presented to `SafeCallFilter` is the `Utility::batch` variant, not the `Staking::reap_stash` variant that `AllExceptReapStash` is designed to catch.
- Assuming `AllExceptReapStash` performs a direct/shallow match on the call variant (the standard, minimal way such filters are implemented in this codebase family, e.g. how `AllSiblingSystemParachains`/`Equals`-style filters are written elsewhere in this file), the outer `Utility::batch` call passes the `SafeCallFilter` check and is dispatched.
- Inside `pallet_utility::batch`, each inner call is dispatched via `call.dispatch(origin)`, which invokes the generated `Dispatchable::dispatch` for `RuntimeCall`. That generated wrapper enforces `frame_system::Config::BaseCallFilter`, not `xcm_executor::Config::SafeCallFilter`. Unless `BaseCallFilter` on this runtime also excludes `reap_stash` (not confirmed from the indexed files), the nested call proceeds to execution.

### Impact Explanation
If confirmed, this allows any XCMP-connected sovereign account (i.e., any sibling parachain, which requires no special governance access — only an established HRMP channel and the ability to send `Transact`) to force-dispatch `Staking::reap_stash` against arbitrary stash accounts on Asset Hub Polkadot, bypassing the explicit exclusion encoded by `AllExceptReapStash`. Since `reap_stash` operates on staking ledgers now hosted on Asset Hub (per `crate::staking::DapStagingAccount` reference in the file) [3](#0-2) , this defeats the specific protective intent the runtime authors encoded via `SafeCallFilter`, undermining the "filters must not be bypassable" invariant even if `reap_stash` itself has internal dust/threshold preconditions that limit direct fund theft.

### Likelihood Explanation
Feasibility depends entirely on two unverified facts I could not confirm from the indexed files:
1. The exact source of `AllExceptReapStash` (its `Contains<RuntimeCall>` implementation) — I located its usage sites but not its definition in the indexed portion of `system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs`.
2. The concrete value of `frame_system::Config::BaseCallFilter` for this runtime, which determines whether the nested dispatch inside `Utility::batch` would independently be blocked.

If `AllExceptReapStash` is a shallow/direct pattern match (the common implementation style) and `BaseCallFilter` is `Everything` or otherwise does not also exclude `reap_stash`, the bypass is trivially reachable by any sibling parachain with an open HRMP channel — no special privilege beyond normal sovereign-account XCM sending capability is required, and it is fully repeatable.

### Recommendation
Make `AllExceptReapStash` recursively inspect composite/dispatch-wrapping calls (`Utility::batch`, `Utility::batch_all`, `Utility::force_batch`, `Utility::as_derivative`, `Proxy::proxy`, `Multisig::as_multi`, etc.) by using `GetDispatchInfo`/`IsSubType`-based unwrapping, or alternatively also add `reap_stash` to `frame_system::Config::BaseCallFilter` so the exclusion is enforced regardless of dispatch path, not solely at the XCM `Transact` entry point.

### Proof of Concept
Rust unit test in `asset-hub-polkadot` runtime tests:
```rust
#[test]
fn safe_call_filter_blocks_reap_stash_via_batch() {
    let inner = RuntimeCall::Staking(pallet_staking::Call::reap_stash {
        stash: AccountId::from([1u8; 32]),
        num_slashing_spans: 0,
    });
    let wrapped = RuntimeCall::Utility(pallet_utility::Call::batch { calls: vec![inner.clone()] });

    // Direct call is correctly blocked.
    assert!(!AllExceptReapStash::contains(&inner));

    // Bypass check: batch-wrapped call should also be blocked but currently is not.
    assert!(!AllExceptReapStash::contains(&wrapped), "SafeCallFilter bypass via Utility::batch");
}
```
Complementary xcm-emulator integration test: from a sibling parachain sovereign origin, send `Xcm(vec![Transact { call: wrapped.encode().into(), .. }])` to Asset Hub Polkadot and assert that `pallet_staking::Ledger::<Runtime>::get(&target_stash)` is unaffected (i.e., the dispatch fails or is filtered), rather than successfully reaped.

### Citations

**File:** system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs (L229-248)
```rust
pub type XcmOriginToTransactDispatchOrigin = (
	// Sovereign account converter; this attempts to derive an `AccountId` from the origin location
	// using `LocationToAccountId` and then turn that into the usual `Signed` origin. Useful for
	// foreign chains who want to have a local sovereign account on this chain which they control.
	SovereignSignedViaLocation<LocationToAccountId, RuntimeOrigin>,
	// Native converter for Relay-chain (Parent) location; will convert to a `Relay` origin when
	// recognised.
	RelayChainAsNative<RelayChainOrigin, RuntimeOrigin>,
	// Native converter for sibling Parachains; will convert to a `SiblingPara` origin when
	// recognised.
	SiblingParachainAsNative<cumulus_pallet_xcm::Origin, RuntimeOrigin>,
	// Superuser converter for the Relay-chain (Parent) location. This will allow it to issue a
	// transaction from the Root origin.
	ParentAsSuperuser<RuntimeOrigin>,
	// Native signed account converter; this just converts an `AccountId32` origin into a normal
	// `RuntimeOrigin::Signed` origin of the same 32-byte value.
	SignedAccountId32AsNative<RelayNetwork, RuntimeOrigin>,
	// Xcm origins can be represented natively under the Xcm pallet's Xcm origin.
	XcmPassthrough<RuntimeOrigin>,
);
```

**File:** system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs (L485-486)
```rust
			ResolveTo<DapStagingAccount, Balances>,
		>,
```

**File:** system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs (L516-518)
```rust
	type CallDispatcher = RuntimeCall;
	type SafeCallFilter = AllExceptReapStash;
	type Aliasers = TrustedAliasers;
```
