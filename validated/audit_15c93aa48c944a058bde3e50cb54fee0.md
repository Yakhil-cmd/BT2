## Analysis Result

This is a real, exploitable bypass. The root cause is that `pallet_xcm::send` is permissively configured on Asset Hub Kusama, and Bridge Hub Kusama's XCM `Barrier` unconditionally trusts the *whole-chain* origin `AssetHubLocation` for free execution — with no distinction between messages that went through `pallet_xcm_bridge_hub_router` (which charges `XcmBridgeHubRouterByteFee`/`XcmBridgeHubRouterBaseFee`) and messages that a normal user hand-crafted and sent directly via plain XCMP to the sibling Bridge Hub.

### Title
Unpaid `ExportMessage` reaches `XcmOverBridgeHubPolkadot` by bypassing `pallet_xcm_bridge_hub_router` fee logic via direct signed `pallet_xcm::send` to Bridge Hub Kusama - (File: system-parachains/bridge-hubs/bridge-hub-kusama/src/xcm_config.rs)

### Summary
A normal signed account on Asset Hub Kusama can call `pallet_xcm::send` with `dest = (1, Parachain(BRIDGE_HUB_KUSAMA_ID))` and a hand-crafted `Xcm([UnpaidExecution{..}, ExportMessage{network: Polkadot, ...}])`. Because this destination is a direct sibling parachain, the message is routed through plain `XcmpQueue` (part of `LocalXcmRouter`) instead of `ToPolkadotXcmRouterInstance`, completely skipping `XcmBridgeHubRouterByteFee`/`XcmBridgeHubRouterFeeAssetId` accounting. On arrival, Bridge Hub Kusama's `Barrier` recognizes the message's transport-origin as `Equals<AssetHubLocation>` (the whole chain's sovereign identity, not the individual signed user) and grants free, unpaid execution, letting `ExportMessage` reach `XcmOverBridgeHubPolkadot` (`type MessageExporter = XcmOverBridgeHubPolkadot;`) for free, since `MessageExportPrice = ()` adds no further charge.

### Finding Description
- On Asset Hub Kusama, `pallet_xcm::Config::SendXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalPalletOrSignedOriginToLocation>`, and `LocalPalletOrSignedOriginToLocation` includes `SignedToAccountId32<...>`, meaning **any normal signed account** can call `pallet_xcm::send` with an arbitrary destination and arbitrary raw `Xcm` program. [1](#0-0) 
- Asset Hub Kusama's `XcmRouter` is `WithUniqueTopic<(LocalXcmRouter, ToPolkadotXcmRouter)>`, where `LocalXcmRouter = (ParentAsUmp, XcmpQueue)` handles delivery to any sibling parachain (including Bridge Hub Kusama) directly, and `ToPolkadotXcmRouterInstance` (the fee/back-pressure-checked `pallet_xcm_bridge_hub_router`) is only invoked when routing crosses into `GlobalConsensus(Polkadot)` via the `NetworkExportTable`/`Bridges` matching logic. [2](#0-1) 
- A user can bypass the router entirely by directly targeting the sibling Bridge Hub parachain location instead of the abstracted `GlobalConsensus(Polkadot)` location, and embed the low-level `ExportMessage` instruction themselves — the router pallet (with its `XcmBridgeHubRouterByteFee`/`XcmBridgeHubRouterFeeAssetId`, `BaseFee`, and `UnpaidExport`/back-pressure config) is simply never entered. [3](#0-2) 
- On Bridge Hub Kusama, the received message's origin is set by the transport layer to the *sending chain's* sovereign location (`Parachain(AssetHubKusama_ID)` = `AssetHubLocation`), not the individual signed account, because `pallet_xcm::send` forwards the raw XCM without inserting `DescendOrigin`.
- Bridge Hub Kusama's `Barrier` explicitly grants `AllowExplicitUnpaidExecutionFrom` to `Equals<AssetHubLocation>` (among others), with no distinction for whether the router already charged a fee: [4](#0-3) 
- The `MessageExporter` for the `XcmConfig` is `XcmOverBridgeHubPolkadot`, and the `pallet_xcm_bridge_hub::Config` sets `MessageExportPrice = ()`, explicitly relying on the (bypassed) upstream fee model rather than charging anything itself: [5](#0-4) [6](#0-5) 
- The comment in `estimate_kusama_to_polkadot_byte_fee` confirms the byte-fee model is specifically designed to charge for "the second part [which] is the payment for bytes of the message delivery transaction, which is 'mined' at Polkadot Bridge Hub" — i.e., relayer compensation for delivering/confirming on the far side — a cost this bypass avoids paying entirely. [7](#0-6) 

### Impact Explanation
An attacker (any signed AssetHubKusama account) can push arbitrary `ExportMessage` payloads into the Kusama→Polkadot outbound bridge lane for free, without paying the router's per-byte/base delivery fee that is meant to fund relayer compensation for delivery+dispatch+confirmation on the Polkadot side. This directly matches the scoped impact: free/underpaid bridge message export, draining relayer subsidy and enabling low-cost congestion of the bridge outbound queue, all while the intended fee/back-pressure mechanism (`pallet_xcm_bridge_hub_router`) is never invoked.

### Likelihood Explanation
Fully reachable by an unprivileged signed user with only ordinary `pallet_xcm::send` permission on Asset Hub Kusama — no special origin, proxy, or governance action required. The only "cost" is the local weight-based execution fee charged by the XCM executor's `Trader` for whatever instructions actually execute — but since the Barrier grants unconditional unpaid execution to `AssetHubLocation`, `UnpaidExecution` can be used and even that cost is avoided. This is trivially repeatable and scriptable.

### Recommendation
Bridge Hub Kusama's `Barrier` should not blanket-trust `Equals<AssetHubLocation>` for unpaid execution of arbitrary instructions including `ExportMessage`; free/unpaid execution from Asset Hub should be scoped so that `ExportMessage` (or any instruction reaching `MessageExporter`) is only allowed when it demonstrably passed through the fee-charging router (e.g., by requiring the message to originate from the `SiblingBridgeHubWithBridgeHubPolkadotInstance`-style pallet-scoped location, or by giving `MessageExportPrice` a real non-zero price independent of the router so that direct sends can't be free even when the top-level Barrier is bypassed).

### Proof of Concept
xcm-emulator test plan:
1. Set up Asset Hub Kusama and Bridge Hub Kusama with an open HRMP channel (as in existing emulator tests).
2. From a normal signed account on Asset Hub Kusama, call `pallet_xcm::send` with `dest = Location::new(1, Parachain(BRIDGE_HUB_KUSAMA_PARACHAIN_ID))` and `message = Xcm(vec![UnpaidExecution { weight_limit: Unlimited, check_origin: None }, ExportMessage { network: NetworkId::Polkadot, destination: [Parachain(ASSET_HUB_ID)].into(), xcm: Xcm(vec![]) }])`.
3. Assert: (a) the call succeeds without touching `pallet_xcm_bridge_hub_router::Instance1` storage/events (no `XcmBridgeHubRouterByteFee`/`BaseFee` deducted, no congestion/back-pressure check triggered), (b) on Bridge Hub Kusama, `BridgePolkadotMessages` outbound queue receives the exported message, and (c) the sender's/AssetHub sovereign account balance on Bridge Hub Kusama is unchanged (zero fee charged), contrasting with `handle_export_message_from_system_parachain_add_to_outbound_queue_works` which shows the expected paid path.

### Citations

**File:** system-parachains/asset-hubs/asset-hub-kusama/src/xcm_config.rs (L464-481)
```rust
/// For routing XCM messages which do not cross local consensus boundary.
pub(crate) type LocalXcmRouter = (
	// Two routers - use UMP to communicate with the relay chain:
	cumulus_primitives_utility::ParentAsUmp<ParachainSystem, PolkadotXcm, PriceForParentDelivery>,
	// ..and XCMP to communicate with the sibling chains.
	XcmpQueue,
);

/// The means for routing XCM messages which are not for local execution into the right message
/// queues.
pub type XcmRouter = WithUniqueTopic<(
	// The means for routing XCM messages which are not for local execution into the right message
	// queues.
	LocalXcmRouter,
	// Router which wraps and sends xcm to BridgeHub to be delivered to the Polkadot
	// GlobalConsensus
	ToPolkadotXcmRouter,
)>;
```

**File:** system-parachains/asset-hubs/asset-hub-kusama/src/xcm_config.rs (L490-496)
```rust
impl pallet_xcm::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	// Any local signed origin can send XCM messages.
	type SendXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalPalletOrSignedOriginToLocation>;
	type XcmRouter = XcmRouter;
	// Any local signed origin can execute XCM messages.
	type ExecuteXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalSignedOriginToLocation>;
```

**File:** system-parachains/asset-hubs/asset-hub-kusama/src/xcm_config.rs (L1159-1181)
```rust

```

**File:** system-parachains/bridge-hubs/bridge-hub-kusama/src/xcm_config.rs (L139-173)
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
>;
```

**File:** system-parachains/bridge-hubs/bridge-hub-kusama/src/xcm_config.rs (L225-229)
```rust
	type FeeManager = XcmFeeManagerFromComponents<
		WaivedLocations,
		SendXcmFeeToAccount<Self::AssetTransactor, RelayTreasuryPalletAccount>,
	>;
	type MessageExporter = XcmOverBridgeHubPolkadot;
```

**File:** system-parachains/bridge-hubs/bridge-hub-kusama/src/bridge_to_polkadot_config.rs (L233-236)
```rust
	// `MessageExportPrice` is simply propagated to the inner `xcm_builder::HaulBlobExporter`, and
	// we do not need or want to add any additional price for exporting here, as it is already
	// covered by the measured weight of the `ExportMessage` instruction.
	type MessageExportPrice = ();
```

**File:** system-parachains/bridge-hubs/bridge-hub-kusama/primitives/src/lib.rs (L149-159)
```rust
/// Compute the per-byte fee that needs to be paid in KSMs by the sender when sending
/// message from Kusama Bridge Hub to Polkadot Bridge Hub.
pub fn estimate_kusama_to_polkadot_byte_fee() -> Balance {
	// the sender pays for the same byte twice:
	// 1) the first part comes from the HRMP, when message travels from Kusama Asset Hub to Kusama
	//    Bridge Hub;
	// 2) the second part is the payment for bytes of the message delivery transaction, which is
	//    "mined" at Polkadot Bridge Hub. Hence, we need to use byte fees from that chain and
	//    convert it to KSMs here.
	convert_from_udot_to_uksm(system_parachains_constants::polkadot::fee::TRANSACTION_BYTE_FEE)
}
```
