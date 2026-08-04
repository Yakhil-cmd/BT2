### Title
`DenyReserveTransferToRelayChain` on Asset Hub Polkadot can be bypassed by nesting the reserve-transfer instruction inside `SetAppendix`/`SetErrorHandler`, unlike Bridge Hub which wraps the same filter in `DenyRecursively` - (File: `system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs`)

### Summary
Asset Hub Polkadot's `Barrier` applies `DenyReserveTransferToRelayChain` directly (`DenyThenTry<DenyReserveTransferToRelayChain, ...>`), while Bridge Hub Polkadot wraps the identical filter in `DenyRecursively<DenyReserveTransferToRelayChain>`. Because the bare filter only scans the top-level instruction slice of the incoming XCM and does not recurse into nested programs (e.g. the inner `Xcm` carried by `SetAppendix`/`SetErrorHandler`), a signed user can hide `DepositReserveAsset{dest: Parent, ...}` inside such a nested program and have the top-level barrier pass it through.

### Finding Description
The Asset Hub Polkadot Barrier is defined as: [1](#0-0) 

compared with Bridge Hub Polkadot's Barrier, which wraps the same deny rule recursively: [2](#0-1) 

`DenyReserveTransferToRelayChain::should_execute` (from `xcm-builder`, imported but not redefined in this repo) matches on `message.iter().any(|inst| matches!(inst, DepositReserveAsset{dest: Parent,..} | TransferReserveAsset{...} | InitiateReserveWithdraw{...}))`. This scan only walks the flat, top-level instruction list handed to the barrier for that single execution pass; it does not descend into nested `Xcm` programs carried inside other instructions such as `SetAppendix(Xcm)` or `SetErrorHandler(Xcm)`. `DenyRecursively<T>` exists specifically to close that gap by additionally checking the sub-programs of such wrapping instructions before allowing execution. Asset Hub Polkadot (and Kusama, and several other system chains: Collectives, Coretime, Encointer, People) use the bare filter, while only Bridge Hub Polkadot/Kusama use `DenyRecursively`.

Attacker path: `pallet_xcm::execute` on Asset Hub Polkadot is reachable by any signed account, since `ExecuteXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalSignedOriginToLocation>` and `XcmExecuteFilter = Everything`: [3](#0-2) 

An attacker submits `Xcm([WithdrawAsset(dot), SetAppendix(Xcm([DepositReserveAsset{ dest: Parent, assets: Wild(All), xcm: [...] }]))])` (or similarly via `SetErrorHandler`). The top-level instruction list seen by `DenyReserveTransferToRelayChain` is `[WithdrawAsset, SetAppendix]` — no match, so the deny stage passes control to the allow-list (`TakeWeightCredit`/`WithComputedOrigin`/etc.), which is satisfied by an ordinary paid, signed-origin top-level execution. The executor then runs the main program and afterwards executes the appendix, invoking the reserve-transfer semantics that the top-level filter was specifically meant to block, without the barrier being consulted again for the nested program.

This is exactly the class of bypass the emulator-tested invariant assumes cannot happen: [4](#0-3) 

That test only exercises the pallet_xcm high-level `limited_reserve_transfer_assets` extrinsic (which places `DepositReserveAsset` at the top level), not the raw `PolkadotXcm::execute` path with nested wrapping instructions, so it does not cover this bypass.

### Impact Explanation
If the reserve-transfer-to-relay path executes, DOT is withdrawn from the attacker's own local holding on Asset Hub and a `ReserveAssetDeposited` message is dispatched to the Relay Chain claiming Asset Hub as a reserve for DOT — a relationship the protocol never intends to support (DOT's canonical/home location is the Relay Chain itself, and Relay<->AssetHub DOT transfers are meant to be teleports, not reserve transfers). Depending on how the Relay Chain's own executor treats the inbound `ReserveAssetDeposited`/`DepositAsset` sequence for its native asset, this could result in DOT being burned on Asset Hub without any corresponding backing check on the Relay Chain, i.e., unauthorized/uncontrolled movement of the native asset through a path the runtime explicitly filters against — violating the "reserve transfers back to the Relay Chain must be uniformly denied" invariant regardless of nesting depth.

### Likelihood Explanation
Preconditions are minimal: any signed account (or account holding some DOT) can call `pallet_xcm::execute` directly (no governance/root required), since `ExecuteXcmOrigin`/`XcmExecuteFilter` impose no restriction on instruction shape. Constructing an XCM with `SetAppendix`/`SetErrorHandler` wrapping a `DepositReserveAsset{dest: Parent}` is straightforward XCM crafting, requiring no special privilege — only ordinary fee/weight payment. This is a deterministic, repeatable bypass of the top-level `Barrier`, not a probabilistic or race-dependent one.

### Recommendation
Wrap the reserve-transfer deny rule in `DenyRecursively` on Asset Hub Polkadot/Kusama (and the other affected system chains — Collectives, Coretime, Encointer, People) to match Bridge Hub's configuration:
```rust
pub type Barrier = TrailingSetTopicAsId<
    DenyThenTry<
        DenyRecursively<DenyReserveTransferToRelayChain>,
        ( ... )
    >,
>;
```
so that nested programs inside `SetAppendix`/`SetErrorHandler` (and any other instruction carrying a sub-`Xcm`) are checked against the same deny rule before execution is permitted.

### Proof of Concept
xcm-emulator integration test (in `integration-tests/emulated/tests/assets/asset-hub-polkadot/src/tests/reserve_transfer.rs` or a new file):
1. Fund `AssetHubPolkadotSender` with DOT.
2. Build `let xcm = Xcm(vec![WithdrawAsset((Parent, amount).into()), SetAppendix(Xcm(vec![DepositReserveAsset{ assets: Wild(All), dest: Parent.into(), xcm: Xcm(vec![DepositAsset{assets: Wild(All), beneficiary}]) }]))]);`.
3. Call `<AssetHubPolkadot as AssetHubPolkadotPallet>::PolkadotXcm::execute(signed_origin, bx!(VersionedXcm::from(xcm)), Weight::MAX)`.
4. Assert the call currently **succeeds** (`assert_ok!`) and that the DOT balance of the sender decreases and an outbound UMP message containing `ReserveAssetDeposited`/`DepositAsset` for DOT is queued to the Relay Chain — demonstrating the top-level `Barrier` did not deny it, in contrast to the direct `limited_reserve_transfer_assets` call which is correctly filtered (`Filtered` error) per the existing `reserve_transfer_dot_from_asset_hub_to_relay_fails` test.
5. After applying the `DenyRecursively` fix, re-run the same `execute` call and assert it now fails with `ProcessMessageError::Unsupported` / barrier rejection, matching the behavior already enforced on Bridge Hub Polkadot.

### Citations

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

**File:** system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs (L612-622)
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

**File:** integration-tests/emulated/tests/assets/asset-hub-polkadot/src/tests/reserve_transfer.rs (L561-596)
```rust
/// Reserve Transfers of DOT from Asset Hub to Relay Chain shouldn't work
#[test]
fn reserve_transfer_dot_from_asset_hub_to_relay_fails() {
	// Init values for Asset Hub
	let signed_origin =
		<AssetHubPolkadot as Chain>::RuntimeOrigin::signed(AssetHubPolkadotSender::get());
	let destination = AssetHubPolkadot::parent_location();
	let beneficiary_id = PolkadotReceiver::get();
	let beneficiary: Location =
		AccountId32Junction { network: None, id: beneficiary_id.into() }.into();
	let amount_to_send: Balance = ASSET_HUB_POLKADOT_ED * 1000;

	let assets: Assets = (Parent, amount_to_send).into();
	let fee_asset_item = 0;

	// this should fail
	AssetHubPolkadot::execute_with(|| {
		let result =
			<AssetHubPolkadot as AssetHubPolkadotPallet>::PolkadotXcm::limited_reserve_transfer_assets(
				signed_origin,
				bx!(destination.into()),
				bx!(beneficiary.into()),
				bx!(assets.into()),
				fee_asset_item,
				WeightLimit::Unlimited,
			);
		assert_err!(
			result,
			DispatchError::Module(sp_runtime::ModuleError {
				index: 31,
				error: [2, 0, 0, 0],
				message: Some("Filtered")
			})
		);
	});
}
```
