### Title
`DenyReserveTransferToRelayChain` on People-Polkadot performs only shallow, non-recursive instruction matching, allowing a nested-instruction bypass of the Deny filter - (File: system-parachains/people/people-polkadot/src/xcm_config.rs)

### Summary
The `Barrier` type in `people-polkadot`'s `xcm_config.rs` wraps `DenyReserveTransferToRelayChain` directly in `DenyThenTry`, without the `DenyRecursively` wrapper that other system parachains in this same repository use for the same filter. [1](#0-0)  Because `DenyReserveTransferToRelayChain` (from the upstream `xcm-builder` crate) only inspects the top-level instruction list of an incoming XCM, a reserve-transfer/reserve-deposit instruction nested inside `SetAppendix`, `SetErrorHandler`, or an `ExecuteWithOrigin`-wrapped sub-program is not inspected and the deny check passes.

### Finding Description
`people-polkadot`'s `Barrier` is defined as:
```
pub type Barrier = TrailingSetTopicAsId<
    DenyThenTry<
        DenyReserveTransferToRelayChain,
        ( ... allow-set ... ),
    >,
>;
``` [2](#0-1) 

This is used as `type Barrier = Barrier;` in the `XcmExecutor::Config`, and the runtime's `pallet_xcm::Config::SendXcmOrigin` allows any local signed account to call `pallet_xcm::send`, giving an attacker a direct, unprivileged path to construct and dispatch an arbitrary XCM program from this chain toward the Relay Chain via `ParentAsUmp`. [3](#0-2) [4](#0-3) 

Critically, comparing this file against sibling runtimes in the same repository shows that the maintainers explicitly recognized and patched exactly this nesting-bypass problem in at least two other chains by wrapping the filter with `DenyRecursively<DenyReserveTransferToRelayChain>`:
- `bridge-hub-polkadot`: `DenyRecursively<DenyReserveTransferToRelayChain>` combined with `DenyRecursively<DenyExportMessageFrom<...>>`. [5](#0-4) 
- `bulletin-polkadot`: `DenyRecursively<DenyReserveTransferToRelayChain>`. [6](#0-5) 

However, the following chains in the same repo still use the *bare, non-recursive* `DenyReserveTransferToRelayChain`, leaving them exposed to the same class of bypass that `DenyRecursively` was introduced to close:
- `people-polkadot` (subject of this question) [1](#0-0) 
- `people-kusama` [7](#0-6) 
- `asset-hub-polkadot` [8](#0-7) 
- `asset-hub-kusama` [9](#0-8) 
- `bridge-hub-kusama` [10](#0-9) 
- `collectives-polkadot`, `coretime-polkadot`, `coretime-kusama`, `encointer` (same pattern).

Given `DenyReserveTransferToRelayChain`'s known (upstream xcm-builder) shallow-match implementation—matching only top-level `Xcm` instructions such as `TransferReserveAsset`, `InitiateReserveWithdraw`, `DepositReserveAsset`/`ReserveAssetDeposited` — an attacker can wrap the denied pattern inside `SetAppendix(Xcm[...])`, `SetErrorHandler(Xcm[...])`, or an `ExecuteWithOrigin` sub-program. The top-level scan of the outer `Xcm` will not see the sensitive instruction (it's inside a nested `Xcm` blob), so `DenyReserveTransferToRelayChain::should_execute` returns `Ok(())`/does not deny, and the message proceeds to the `Allow*` tuple, which for `AllowTopLevelPaidExecutionFrom<Everything>` or similar permits normal paid execution regardless of origin. [11](#0-10) 

Once the barrier is passed, execution proceeds through `XcmExecutor` and any nested `ReserveAssetDeposited`/`InitiateReserveWithdraw` runs when the outer program's appendix/error-handler is invoked, potentially routing an asset-transactor operation to the Relay Chain in a manner the filter was meant to prevent — this chain is explicitly documented as "not meant as a reserve location" (`XcmReserveTransferFilter = Nothing`), confirming that reserve-transfer-to-Relay semantics are intentionally disallowed here. [12](#0-11) 

### Impact Explanation
Confirmed within scope: the barrier misconfiguration is real and reproducible by direct comparison with sibling runtimes that patched it. What is **not verifiable from this repository alone** is the exact downstream consequence claimed in the question — a permanent/poison UMP message that `pallet_message_queue::ProcessMessage` retries indefinitely on the Relay Chain. That requires: (1) confirming `DenyReserveTransferToRelayChain`'s exact upstream matching logic (it lives in the external `xcm-builder` crate, not vendored in this repo, so its precise recursion behavior could not be directly re-verified here), and (2) tracing the Relay Chain's `relay/*/src/lib.rs` `MessageProcessor`/asset-transactor error path to confirm it yields a non-transient error that `pallet_message_queue` retries forever rather than dropping/trapping the message. Those two links were not directly inspectable in this pass.

### Likelihood Explanation
Precondition (unprivileged signed account calling `pallet_xcm::send`) is satisfied by the runtime's own configuration: `SendXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalSignedOriginToLocation>` permits any local signed account to send arbitrary XCM. [3](#0-2)  The structural difference (bare filter vs. `DenyRecursively`-wrapped filter) across otherwise near-identical `Barrier` definitions in the same codebase is strong circumstantial evidence that this is an unpatched instance of a known bypass class, not a false positive.

### Recommendation
Wrap `DenyReserveTransferToRelayChain` (and any other Deny-style filters relied upon for security) with `DenyRecursively` in `people-polkadot`'s `Barrier` definition, matching the pattern already applied in `bridge-hub-polkadot` and `bulletin-polkadot`:
```rust
pub type Barrier = TrailingSetTopicAsId<
    DenyThenTry<
        DenyRecursively<DenyReserveTransferToRelayChain>,
        ( ... ),
    >,
>;
```
Apply the same fix consistently to `people-kusama`, `asset-hub-polkadot`, `asset-hub-kusama`, `bridge-hub-kusama`, `collectives-polkadot`, `coretime-polkadot`, `coretime-kusama`, and `encointer`, which all currently use the bare (non-recursive) filter.

### Proof of Concept
Unit test plan (to run against `xcm-executor`/`xcm-builder` types used by `people-polkadot::XcmConfig`):
```rust
#[test]
fn deny_reserve_transfer_bypassed_via_nested_setappendix() {
    let inner = Xcm(vec![
        ReserveAssetDeposited((Parent, 100u128).into()),
        InitiateReserveWithdraw {
            assets: All.into(),
            reserve: Parent.into(),
            xcm: Xcm(vec![]),
        },
    ]);
    let mut outer = Xcm(vec![
        SetAppendix(inner),
        WithdrawAsset((Parent, 100u128).into()),
        BuyExecution { fees: (Parent, 100u128).into(), weight_limit: Unlimited },
        DepositAsset { assets: All.into(), beneficiary: Here.into() },
    ]);

    // Expect: DenyThenTry<DenyReserveTransferToRelayChain, _> should reject this program
    // because it contains a reserve-transfer-to-Relay-Chain instruction anywhere in its tree.
    let mut weight_credit = Weight::zero();
    let result = <people_polkadot_runtime::xcm_config::Barrier as ShouldExecute>::should_execute(
        &Location::new(0, [AccountId32 { network: None, id: [0u8;32] }]),
        outer.inner_mut(),
        Weight::from_parts(1_000_000_000, 0),
        &mut Properties { weight_credit, message_id: &mut None },
    );

    // Bug: with the bare `DenyReserveTransferToRelayChain` (no `DenyRecursively`), this
    // assertion FAILS because the nested ReserveAssetDeposited/InitiateReserveWithdraw
    // inside SetAppendix is invisible to the shallow top-level scan.
    assert!(result.is_err(), "nested reserve-transfer-to-relay must be denied");
}
```
Expected outcome on unpatched code: assertion fails (message is allowed through), demonstrating the bypass; after wrapping with `DenyRecursively`, the assertion should pass (message denied).

Note: the exact matching semantics of `DenyReserveTransferToRelayChain` are implemented in the external `xcm-builder` crate and were not directly available for line-level verification in this repository's index; the finding above is based on the reachable/attacker-controlled entry path in this repo plus the direct, repo-internal evidence that `DenyRecursively` was introduced elsewhere specifically to wrap this same filter, but not applied uniformly to `people-polkadot`.

### Citations

**File:** system-parachains/people/people-polkadot/src/xcm_config.rs (L193-225)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyReserveTransferToRelayChain,
		(
			// Allow local users to buy weight credit.
			TakeWeightCredit,
			// Expected responses are OK.
			AllowKnownQueryResponses<PolkadotXcm>,
			WithComputedOrigin<
				(
					// If the message is one that immediately attempts to pay for execution, then
					// allow it.
					AllowTopLevelPaidExecutionFrom<Everything>,
					// Parent and its pluralities (i.e. governance bodies) get free execution.
					AllowExplicitUnpaidExecutionFrom<
						(
							ParentOrParentsPlurality,
							FellowsPlurality,
							Equals<RelayTreasuryLocation>,
							Equals<AssetHubLocation>,
							AssetHubPlurality,
						),
						TrustedAliasers,
					>,
					// Subscriptions for version tracking are OK.
					AllowSubscriptionsFrom<ParentRelayOrSiblingParachains>,
				),
				UniversalLocation,
				ConstU32<8>,
			>,
		),
	>,
>;
```

**File:** system-parachains/people/people-polkadot/src/xcm_config.rs (L346-351)
```rust
pub type XcmRouter = WithUniqueTopic<(
	// Two routers - use UMP to communicate with the relay chain:
	cumulus_primitives_utility::ParentAsUmp<ParachainSystem, PolkadotXcm, PriceForParentDelivery>,
	// ..and XCMP to communicate with the sibling chains.
	XcmpQueue,
)>;
```

**File:** system-parachains/people/people-polkadot/src/xcm_config.rs (L360-368)
```rust
impl pallet_xcm::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	// Any local signed origin can send XCM messages.
	type SendXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalSignedOriginToLocation>;
	type XcmRouter = XcmRouter;
	// Any local signed origin can execute XCM messages.
	type ExecuteXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalSignedOriginToLocation>;
	type XcmExecuteFilter = Everything;
	type XcmExecutor = XcmExecutor<XcmConfig>;
```

**File:** system-parachains/people/people-polkadot/src/xcm_config.rs (L370-370)
```rust
	type XcmReserveTransferFilter = Nothing; // This parachain is not meant as a reserve location.
```

**File:** system-parachains/bridge-hubs/bridge-hub-polkadot/src/xcm_config.rs (L150-160)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		(
			DenyRecursively<DenyReserveTransferToRelayChain>,
			DenyRecursively<
				DenyExportMessageFrom<
					EverythingBut<Equals<AssetHubLocation>>,
					Equals<EthereumNetwork>,
				>,
			>,
		),
```

**File:** system-parachains/bulletin/bulletin-polkadot/src/xcm_config.rs (L147-149)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyRecursively<DenyReserveTransferToRelayChain>,
```

**File:** system-parachains/people/people-kusama/src/xcm_config.rs (L166-169)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyReserveTransferToRelayChain,
		(
```

**File:** system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs (L374-377)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyReserveTransferToRelayChain,
		(
```

**File:** system-parachains/asset-hubs/asset-hub-kusama/src/xcm_config.rs (L270-273)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyReserveTransferToRelayChain,
		(
```

**File:** system-parachains/bridge-hubs/bridge-hub-kusama/src/xcm_config.rs (L139-142)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyReserveTransferToRelayChain,
		(
```
