### Title
`DenyReserveTransferToRelayChain` in Asset Hub Polkadot's `Barrier` only inspects top-level XCM instructions, allowing reserve-transfer-to-Relay-Chain instructions nested in `SetAppendix`/`SetErrorHandler` to bypass the deny filter - (File: system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs)

### Summary
The `Barrier` type in `asset-hub-polkadot` wires `DenyReserveTransferToRelayChain` directly into `DenyThenTry` without the `DenyRecursively` wrapper [1](#0-0) . `DenyReserveTransferToRelayChain` (from `xcm_builder`) evaluates only the top-level instruction slice passed to `should_execute`, so a `DepositReserveAsset{dest: Parent, ..}` nested inside a `SetAppendix`/`SetErrorHandler` sub-program is invisible to the deny check, while it still executes later when the appendix/error-handler runs.

### Finding Description
The `Barrier` for `asset-hub-polkadot` is defined as:
```
DenyThenTry<
    DenyReserveTransferToRelayChain,
    ( TakeWeightCredit, AllowKnownQueryResponses<...>, WithComputedOrigin<...> ),
>
``` [2](#0-1) 

`DenyReserveTransferToRelayChain` is imported from upstream `xcm_builder` [3](#0-2)  and its `should_execute` implementation only iterates the flat `message` slice looking for `InitiateReserveWithdraw`/`DepositReserveAsset`/`TransferReserveAsset` instructions targeting `(1, Here)`. It does not descend into instructions that themselves carry nested `Xcm` programs (`SetAppendix(Xcm<Call>)`, `SetErrorHandler(Xcm<Call>)`). Because those nested programs are only scanned by the top-level `.iter()` as an opaque `SetAppendix`/`SetErrorHandler` variant (not unwrapped), a `DepositReserveAsset{dest: Parent}` buried inside them is never matched, so the deny check returns `Ok(())` (does not deny) for the outer message.

Critically, the codebase itself demonstrates awareness of this limitation: `bridge-hub-polkadot` and `bulletin-polkadot` wrap the same primitive in `DenyRecursively<DenyReserveTransferToRelayChain>` [4](#0-3) [5](#0-4) , which recursively unwraps `SetAppendix`/`SetErrorHandler` (and other nesting instructions) before applying the deny predicate. `asset-hub-polkadot`, `asset-hub-kusama`, `collectives-polkadot`, `coretime-kusama`, `coretime-polkadot`, `people-kusama`, and `people-polkadot` all still use the bare, non-recursive `DenyReserveTransferToRelayChain` [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) , so all of these remain exposed to the same bypass.

Attacker path: a signed user on Asset Hub Polkadot holding DOT can call `pallet_xcm::execute` (a user-callable extrinsic, permission-gated only by the runtime's `XcmExecuteFilter`, not by content-aware barrier logic) with a local program such as:
```
Xcm(vec![
    SetErrorHandler(Xcm(vec![DepositReserveAsset { assets: All.into(), dest: Parent.into(), xcm: Xcm(vec![]) }])),
    WithdrawAsset(...),   // benign top-level instructions to pass AllowTopLevelPaidExecutionFrom
    BuyExecution { .. },
    <some instruction that triggers an error, invoking the error handler>
])
```
The top-level scan in `DenyReserveTransferToRelayChain` sees `SetErrorHandler`, `WithdrawAsset`, `BuyExecution`, etc. — never a bare `DepositReserveAsset{dest: Parent}` — so `deny` passes. The remaining `(TakeWeightCredit, AllowKnownQueryResponses, WithComputedOrigin<(AllowTopLevelPaidExecutionFrom<Everything>, ...)>)` chain only checks for `BuyExecution`/paid-execution shape at the top level and origin computation, not the semantic content of `SetAppendix`/`SetErrorHandler`, so the whole message is allowed to execute. When the runtime later triggers the error path (or, with `SetAppendix`, unconditionally at program completion), the nested `DepositReserveAsset{dest: Parent}` executes, moving the attacker's reserve asset to the Relay Chain — precisely the operation the top-level deny rule exists to forbid.

### Impact Explanation
This bypasses an explicit runtime-level invariant ("never allow reserve-transfer/initiate-reserve-withdraw to the Relay Chain from this parachain via barrier"), letting an unprivileged signed user move DOT (or other reserve assets) to the Relay Chain outside the intended, accounted reserve-transfer path (`limited_reserve_transfer_assets`/teleport logic), which can desynchronize reserve backing accounting between Asset Hub and the Relay Chain and circumvent whatever policy reason motivated denying this route (e.g., avoiding double-reserve or unsupported reserve semantics for DOT reserve-transfers off Asset Hub).

### Likelihood Explanation
Feasible with only a signed account and its own funds: `pallet_xcm::execute` is a standard user-facing extrinsic; constructing a well-formed `SetAppendix`/`SetErrorHandler`-wrapped `DepositReserveAsset` is straightforward XCM construction, requiring no special origin or governance. No proxy, bridge, or privileged step is required. The bug is deterministic and repeatable on every call, limited only by the attacker needing enough asset balance to pay execution fees.

### Recommendation
Wrap `DenyReserveTransferToRelayChain` in `DenyRecursively` in `asset-hub-polkadot`'s (and `asset-hub-kusama`'s, `collectives-polkadot`'s, `coretime-*`'s, `people-*`'s) `Barrier` definitions, matching the pattern already used in `bridge-hub-polkadot`/`bulletin-polkadot`:
```rust
pub type Barrier = TrailingSetTopicAsId<
    DenyThenTry<
        DenyRecursively<DenyReserveTransferToRelayChain>,
        ( ... ),
    >,
>;
```

### Proof of Concept
xcm-emulator / integration test plan (to be added under `integration-tests/emulated/tests/assets/asset-hub-polkadot`):
1. As `AssetHubPolkadotSender` (a normal signed account), call `PolkadotXcm::execute` with a hand-built `Xcm` program whose top-level instructions are benign (`WithdrawAsset`, `BuyExecution`) but which sets `SetAppendix(Xcm(vec![DepositReserveAsset{ assets: All.into(), dest: Location::parent(), xcm: Xcm(vec![]) }]))`.
2. Assert the extrinsic result is `Ok` / does *not* return `Filtered`/`Barrier` error, demonstrating the barrier failed to deny it (contrast with the existing top-level test `reserve_transfer_ksm_from_asset_hub_to_relay_fails` at `integration-tests/emulated/tests/assets/asset-hub-kusama/src/tests/reserve_transfer.rs:561-597`, which asserts `Filtered` for the *direct* top-level call).
3. Assert that after execution, the account's reserve asset balance on Asset Hub decreased and a corresponding `ReserveAssetDeposited`/UMP message reached the Relay Chain, confirming assets moved to the Relay Chain despite the deny rule.
4. Add a unit test directly against `Barrier::should_execute` feeding a message `[SetAppendix(Xcm(vec![DepositReserveAsset{dest: Parent,..}])), ...]` and assert it currently returns `Ok(())` (bug) vs. `Err(_)` after applying `DenyRecursively` (fix).

### Citations

**File:** system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs (L59-72)
```rust
use xcm_builder::{
	AccountId32Aliases, AliasChildLocation, AliasOriginRootUsingFilter,
	AllowExplicitUnpaidExecutionFrom, AllowKnownQueryResponses, AllowSubscriptionsFrom,
	AllowTopLevelPaidExecutionFrom, DenyReserveTransferToRelayChain, DenyThenTry,
	DescribeAllTerminal, DescribeFamily, EnsureXcmOrigin, ExternalConsensusLocationsConverterFor,
	FrameTransactionalProcessor, FungibleAdapter, FungiblesAdapter, HashedDescription, IsConcrete,
	IsSiblingSystemParachain, LocalMint, MatchedConvertedConcreteId, MintLocation, NoChecking,
	OriginToPluralityVoice, ParentAsSuperuser, ParentIsPreset, RelayChainAsNative,
	SendXcmFeeToAccount, SiblingParachainAsNative, SiblingParachainConvertsVia,
	SignedAccountId32AsNative, SignedToAccountId32, SingleAssetExchangeAdapter,
	SovereignSignedViaLocation, StartsWith, StartsWithExplicitGlobalConsensus, TakeWeightCredit,
	TrailingSetTopicAsId, UnpaidRemoteExporter, UsingComponents, WeightInfoBounds,
	WithComputedOrigin, WithLatestLocationConverter, WithUniqueTopic, XcmFeeManagerFromComponents,
};
```

**File:** system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs (L374-409)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyReserveTransferToRelayChain,
		(
			TakeWeightCredit,
			// Expected responses are OK.
			AllowKnownQueryResponses<PolkadotXcm>,
			// Allow XCMs with some computed origins to pass through.
			WithComputedOrigin<
				(
					// If the message is one that immediately attempts to pay for execution, then
					// allow it.
					AllowTopLevelPaidExecutionFrom<Everything>,
					// The locations listed below get free execution.
					// Parent, its pluralities (i.e. governance bodies), the Fellows plurality and
					// sibling bridge hub get free execution.
					AllowExplicitUnpaidExecutionFrom<
						(
							ParentOrParentsPlurality,
							FellowshipEntities,
							Equals<RelayTreasuryLocation>,
							Equals<bridging::SiblingBridgeHub>,
							AmbassadorEntities,
							IsSiblingSystemParachain<ParaId, parachain_info::Pallet<Runtime>>,
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

**File:** system-parachains/bulletin/bulletin-polkadot/src/xcm_config.rs (L147-150)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyRecursively<DenyReserveTransferToRelayChain>,
		(
```

**File:** system-parachains/collectives/collectives-polkadot/src/xcm_config.rs (L168-169)
```rust
	DenyThenTry<
		DenyReserveTransferToRelayChain,
```

**File:** system-parachains/coretime/coretime-polkadot/src/xcm_config.rs (L160-161)
```rust
	DenyThenTry<
		DenyReserveTransferToRelayChain,
```

**File:** system-parachains/people/people-polkadot/src/xcm_config.rs (L194-195)
```rust
	DenyThenTry<
		DenyReserveTransferToRelayChain,
```
