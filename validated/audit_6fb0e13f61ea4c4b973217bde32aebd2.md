### Title
`DenyReserveTransferToRelayChain` on BridgeHub-Kusama is not wrapped in `DenyRecursively`, allowing reserve-transfer-to-Relay instructions nested in `SetAppendix`/`SetErrorHandler` to bypass the Deny barrier - (File: system-parachains/bridge-hubs/bridge-hub-kusama/src/xcm_config.rs)

### Summary
The `Barrier` type on BridgeHub-Kusama uses `DenyThenTry<DenyReserveTransferToRelayChain, ...>` directly, while the equivalent barrier on BridgeHub-Polkadot and Bulletin-Polkadot wraps the same check as `DenyRecursively<DenyReserveTransferToRelayChain>`. `DenyReserveTransferToRelayChain::should_execute` only scans the top-level instruction slice for `InitiateReserveWithdraw`/`DepositReserveAsset`/`TransferReserveAsset` targeting `Location{parents:1, interior:Here}`; it does not descend into nested `Xcm` programs embedded inside `SetAppendix`, `SetErrorHandler`, or similar instructions, which is exactly the gap `DenyRecursively` was introduced to close.

### Finding Description
`Barrier` is defined at [1](#0-0)  as `TrailingSetTopicAsId<DenyThenTry<DenyReserveTransferToRelayChain, (...)>>`, with `DenyReserveTransferToRelayChain` used un-wrapped. By contrast, the sibling chain BridgeHub-Polkadot defines its barrier as `DenyThenTry<(DenyRecursively<DenyReserveTransferToRelayChain>, DenyRecursively<DenyExportMessageFrom<...>>), (...)>` at [2](#0-1) , and Bulletin-Polkadot similarly uses `DenyRecursively<DenyReserveTransferToRelayChain>` at [3](#0-2) .

`DenyReserveTransferToRelayChain::should_execute` (xcm-builder) only iterates the flat top-level `message: &mut [Instruction<RuntimeCall>]` slice passed by the executor at the start of `execute_xcm`, checking each instruction for a direct match against `InitiateReserveWithdraw`, `DepositReserveAsset`, or `TransferReserveAsset` with `dest`/`reserve` equal to the Relay Chain (`Parent`, `Here`). It does not recurse into the inner `Xcm` payloads carried by `SetAppendix(xcm)` or `SetErrorHandler(xcm)` (or `ExecuteWithOrigin`), because those payloads are not part of the top-level slice — they are executed later by the executor's `process_error_handler`/`process_appendix` logic without ever re-invoking `Config::Barrier::should_execute`. `DenyRecursively` exists specifically to descend into these nested program fields and apply the inner check recursively; its absence on BridgeHub-Kusama means an attacker can bury `DepositReserveAsset{ dest: Parent, .. }` or `InitiateReserveWithdraw{ reserve: Parent, .. }` inside a `SetErrorHandler`/`SetAppendix` instruction at the top level. The barrier only inspects the outer instructions (e.g. `SetErrorHandler`, `ClearOrigin`, etc.) themselves — never their inner `Xcm` bodies — so the Deny check passes, and once the outer program triggers an error (or completes, for appendix), the nested reserve-transfer-to-Relay instruction executes as part of `IsReserve = ()` accounting flow, attempting a movement that the chain's `IsReserve` config assumes can never occur.

### Impact Explanation
This breaks the explicit invariant that BridgeHub must always deny reserve transfers targeting the Relay Chain (documented and enforced elsewhere as `IsReserve = ()`). An attacker with any reachable XCM entry to BridgeHub-Kusama (sibling `XcmpQueue`, DMP from Relay, or `pallet_xcm::execute`) can smuggle a `DepositReserveAsset`/`InitiateReserveWithdraw`/`TransferReserveAsset` targeting the Relay Chain inside a `SetErrorHandler`/`SetAppendix` payload, causing unauthorized reserve-asset accounting/movement toward the Relay Chain that the barrier was specifically designed to prevent.

### Likelihood Explanation
Feasibility is high and requires no special privilege: it only needs an XCM message reachable through normal sibling/relay channels or `PolkadotXcm::execute`, structured with the deny-triggering instruction nested inside `SetErrorHandler`/`SetAppendix` rather than at the top level. The bug is fully deterministic/reproducible since it stems from a static type-level configuration gap (missing `DenyRecursively` wrapper) rather than a race condition or off-chain assumption.

### Recommendation
Wrap `DenyReserveTransferToRelayChain` in `DenyRecursively` in the BridgeHub-Kusama `Barrier` definition, matching BridgeHub-Polkadot and Bulletin-Polkadot: change `DenyThenTry<DenyReserveTransferToRelayChain, (...)>` to `DenyThenTry<DenyRecursively<DenyReserveTransferToRelayChain>, (...)>` at [4](#0-3) .

### Proof of Concept
xcm-emulator integration test plan (analogous to existing `reserve_transfer_ksm_from_asset_hub_to_relay_fails` at [5](#0-4) , but targeting BridgeHub-Kusama):
1. From a sibling parachain (or via `PolkadotXcm::execute` as a signed BridgeHub-Kusama account), send/execute:
```
Xcm(vec![
    WithdrawAsset(fee_asset.clone().into()),
    BuyExecution { fees: fee_asset.clone(), weight_limit: Unlimited },
    SetErrorHandler(Xcm(vec![
        DepositReserveAsset { assets: Wild(All), dest: Parent.into(), xcm: Xcm(vec![]) },
    ])),
    Trap(0), // forces an error, triggering the error handler
])
```
2. Assert that on current BridgeHub-Kusama code, this message is **not** filtered/denied by the `Barrier` (i.e., it passes `should_execute` and the error handler executes), demonstrating the bypass — contrasted with an equivalent top-level `DepositReserveAsset{dest: Parent}` which correctly gets `ProcessMessageError::Unsupported`/`Filtered`.
3. After applying the fix (`DenyRecursively<DenyReserveTransferToRelayChain>`), assert the same nested-instruction message is denied/filtered identically to the top-level case.

### Citations

**File:** system-parachains/bridge-hubs/bridge-hub-kusama/src/xcm_config.rs (L139-172)
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
					// Parent and its pluralities (i.e. governance bodies) and relay treasury get
					// free execution.
					AllowExplicitUnpaidExecutionFrom<
						(
							ParentOrParentsPlurality,
							Equals<RelayTreasuryLocation>,
							Equals<AssetHubLocation>,
							AssetHubPlurality,
						),
						TrustedAliasers,
					>,
					// Subscriptions for version tracking are OK.
					AllowSubscriptionsFrom<ParentRelayOrSiblingParachains>,
					// HRMP notifications from the relay chain are OK.
					AllowHrmpNotificationsFromRelayChain,
				),
				UniversalLocation,
				ConstU32<8>,
			>,
		),
	>,
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

**File:** integration-tests/emulated/tests/assets/asset-hub-kusama/src/tests/reserve_transfer.rs (L561-596)
```rust
/// Reserve Transfers of KSM from Asset Hub to Relay Chain shouldn't work
#[test]
fn reserve_transfer_ksm_from_asset_hub_to_relay_fails() {
	// Init values for Asset Hub
	let signed_origin =
		<AssetHubKusama as Chain>::RuntimeOrigin::signed(AssetHubKusamaSender::get());
	let destination = AssetHubKusama::parent_location();
	let beneficiary_id = KusamaReceiver::get();
	let beneficiary: Location =
		AccountId32Junction { network: None, id: beneficiary_id.into() }.into();
	let amount_to_send: Balance = ASSET_HUB_KUSAMA_ED * 1000;

	let assets: Assets = (Parent, amount_to_send).into();
	let fee_asset_item = 0;

	// this should fail
	AssetHubKusama::execute_with(|| {
		let result =
			<AssetHubKusama as AssetHubKusamaPallet>::PolkadotXcm::limited_reserve_transfer_assets(
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
