### Title
`DenyReserveTransferToRelayChain` barrier can be bypassed via nested `SetAppendix`/`SetErrorHandler` XCM to reserve-withdraw KSM back to the Relay Chain - (File: system-parachains/asset-hubs/asset-hub-kusama/src/xcm_config.rs)

### Summary
Asset Hub Kusama's `Barrier` wraps `DenyReserveTransferToRelayChain` directly (not `DenyRecursively<DenyReserveTransferToRelayChain>`), so the deny check only inspects the top-level instruction sequence of an incoming XCM program. An attacker-controlled signed account can call `pallet_xcm::execute` with a top-level program that passes the filter, while hiding `InitiateReserveWithdraw{ reserve: Parent, .. }` inside a `SetAppendix`/`SetErrorHandler` nested program, which the executor runs after the main program without re-invoking the Barrier.

### Finding Description
On Asset Hub Kusama, the `Barrier` type is: [1](#0-0) 
using plain `DenyReserveTransferToRelayChain` — unlike Bridge Hub Polkadot and Bulletin Polkadot in the same codebase, which explicitly wrap it as `DenyRecursively<DenyReserveTransferToRelayChain>` to defend against nested bypasses: [2](#0-1) [3](#0-2) 

`DenyReserveTransferToRelayChain::should_execute` (from `xcm-builder`, not vendored in this repo) matches only the outer instruction list for `InitiateReserveWithdraw`/`DepositReserveAsset`/`TransferReserveAsset` targeting the Relay Chain. It does not recurse into the nested `Xcm` programs carried by `SetAppendix`, `SetErrorHandler`, or the `xcm` field of instructions themselves. The Barrier is invoked once, before the executor begins running the top-level program; appendices/error handlers execute later inside the same executor run without a second Barrier check.

Asset Hub Kusama's `pallet_xcm::Config` allows any signed account to call `execute` with an arbitrary program and no restrictive `XcmExecuteFilter`: [4](#0-3) 

Exploit flow: a signed user submits `PolkadotXcm::execute` with a program such as `[WithdrawAsset(KSM), SetAppendix(Xcm([InitiateReserveWithdraw{ reserve: Parent, assets: All, xcm: [...] }]))]`. The top-level instructions (`WithdrawAsset`, `SetAppendix`) do not match the deny pattern, so `should_execute` passes. After the (trivial) main program completes, the executor runs the appendix, which performs `InitiateReserveWithdraw` targeting the Relay Chain — the exact operation the deny filter was meant to block, and exactly what `reserve_transfer_ksm_from_asset_hub_to_relay_fails` asserts is rejected via the top-level extrinsic path.

### Impact Explanation
Successful execution allows an unprivileged signed user to route KSM back to the Relay Chain via the reserve-withdraw path instead of the intended teleport path, contradicting the deny-filter's purpose and the `Filtered` error contract validated by the existing test. Depending on how the Relay Chain (or downstream `IsReserve`/accounting logic) actually interprets an unexpected reserve-withdraw message for a system-teleported asset like KSM, this can create asset-accounting inconsistencies between Asset Hub and the Relay Chain (burn locally with unmatched relay-side release/trap behavior), i.e., a bypass of a documented security control rather than a benign no-op.

### Likelihood Explanation
Preconditions are minimal and fully attacker-controlled: any signed account with some KSM balance and no special privileges. `pallet_xcm::execute` is reachable with `XcmExecuteFilter = Everything`, and constructing `SetAppendix`/`SetErrorHandler` wrapping instructions is standard XCM composition requiring no special permissions. The bypass is deterministic and repeatable on every attempt, limited only by the attacker's willingness to spend the KSM being moved and the fee/weight cost.

### Recommendation
Wrap `DenyReserveTransferToRelayChain` with `DenyRecursively` in Asset Hub Kusama's (and Asset Hub Polkadot's, coretime's, collectives', people's, encointer's) `Barrier` definition, matching the pattern already used in `bridge-hub-polkadot` and `bulletin-polkadot`:
```rust
pub type Barrier = TrailingSetTopicAsId<
    DenyThenTry<
        DenyRecursively<DenyReserveTransferToRelayChain>,
        ( /* ... */ ),
    >,
>;
```
so that nested instructions inside `SetAppendix`, `SetErrorHandler`, and other embedded `Xcm` programs are also checked against the deny rule.

### Proof of Concept
Extend `integration-tests/emulated/tests/assets/asset-hub-kusama/.../reserve_transfer.rs` with a new xcm-emulator test mirroring `reserve_transfer_ksm_from_asset_hub_to_relay_fails`, but instead of calling `limited_reserve_transfer_assets` directly, call `PolkadotXcm::execute` with a program that wraps the forbidden instruction:
```rust
let message = Xcm(vec![
    WithdrawAsset((Here, amount).into()),
    SetAppendix(Xcm(vec![
        InitiateReserveWithdraw {
            assets: All.into(),
            reserve: Parent.into(),
            xcm: Xcm(vec![DepositAsset { assets: All.into(), beneficiary }]),
        },
    ])),
]);
let result = PolkadotXcm::execute(
    signed_origin,
    bx!(xcm::VersionedXcm::from(message)),
    Weight::from_parts(10_000_000_000, 1_000_000),
);
```
Assertion: the test should assert the call is rejected with `Filtered` (same as the top-level case), and additionally assert no KSM leaves the sender's account / no UMP message is queued to the Relay Chain. If, instead, the appendix executes and the reserve-withdraw message is dispatched to the Relay Chain, the finding is confirmed.

### Citations

**File:** system-parachains/asset-hubs/asset-hub-kusama/src/xcm_config.rs (L270-273)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyReserveTransferToRelayChain,
		(
```

**File:** system-parachains/asset-hubs/asset-hub-kusama/src/xcm_config.rs (L490-500)
```rust
impl pallet_xcm::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	// Any local signed origin can send XCM messages.
	type SendXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalPalletOrSignedOriginToLocation>;
	type XcmRouter = XcmRouter;
	// Any local signed origin can execute XCM messages.
	type ExecuteXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalSignedOriginToLocation>;
	type XcmExecuteFilter = Everything;
	type XcmExecutor = XcmExecutor<XcmConfig>;
	type XcmTeleportFilter = Everything;
	type XcmReserveTransferFilter = Everything;
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
