#No vulnerability found for this question.

Analysis: The claimed behavior is real (a bounded shared outbound lane can be filled to `MAX_UNCONFIRMED_MESSAGES_IN_CONFIRMATION_TX` by a normal fee-paying user), but it is an intentional, documented design bound rather than a missing check or logic error. [1](#0-0) 

The `MAX_UNCONFIRMED_MESSAGES_IN_CONFIRMATION_TX` constant exists specifically to bound the weight of `receive_messages_delivery_proof`/`receive_messages_proof` extrinsics (per the comment referencing `check_message_lane_weights`), not as an accidental limit. This is a well-known, self-healing capacity bound of `pallet_bridge_messages` shared by design across all users of a lane — filling it costs the attacker real, non-trivial fees for ~2024 separate messages, and the lane automatically drains as soon as any relayer (economically incentivized via `DeliveryRewardInBalance` and `PriorityBoostPerMessage`) submits a delivery confirmation, which is routine, expected relayer behavior rather than a rare/ungoverned event. [2](#0-1) [3](#0-2) 

Separately, congestion on the AssetHub↔BridgeHub XCMP channel (a distinct, earlier-triggered protection) is actively monitored via `CongestionManager`/`is_congested`, which suspends/resumes the bridge and notifies the sending chain, providing an operational signal and mitigating unbounded queue growth before the `pallet_bridge_messages` bound would even be reached in most scenarios. [4](#0-3) 

The `OpenBridgeOrigin = EnsureNever<Location>` restriction is unrelated to this queue-exhaustion scenario — it only prevents creation of *additional* lanes; it does not affect the fee-based, self-recovering nature of the existing single lane's capacity bound. [5](#0-4) 

Because the root cause is an intentional, documented capacity bound (not a missing check, bad accounting, replay, origin-confusion, or logic error) and the impact is a temporary, self-healing, economically-costly griefing condition rather than an "indefinite halt with no recovery path," this does not meet the "Valid Only If" criteria (specifically criteria 2 and 5) for a reportable runtime bug in this scope.

### Citations

**File:** system-parachains/bridge-hubs/bridge-hub-kusama/primitives/src/lib.rs (L85-89)
```rust
	/// This constant limits the maximum number of messages in `receive_messages_proof`.
	/// We need to adjust it from 4096 to 2024 due to the actual weights identified by
	/// `check_message_lane_weights`. A higher value can be set once we switch
	/// `max_extrinsic_weight` to `BlockWeightsForAsyncBacking`.
	const MAX_UNCONFIRMED_MESSAGES_IN_CONFIRMATION_TX: MessageNonce = 2024;
```

**File:** system-parachains/bridge-hubs/bridge-hub-kusama/src/bridge_to_polkadot_config.rs (L51-67)
```rust
// Parameters that may be changed by the governance.
parameter_types! {
	/// Reward that is paid (by the Kusama Asset Hub) to relayers for delivering a single
	/// Kusama -> Polkadot bridge message.
	///
	/// This payment is tracked by the `pallet_bridge_relayers` pallet at the Kusama
	/// Bridge Hub.
	pub storage DeliveryRewardInBalance: Balance = constants::currency::UNITS / 10_000;

	/// Registered relayer stake.
	///
	/// Any relayer may reserve this amount on his account and get a priority boost for his
	/// message delivery transactions. In exchange, he risks losing his stake if he would
	/// submit an invalid transaction. The set of such (registered) relayers is tracked
	/// by the `pallet_bridge_relayers` pallet at the Kusama Bridge Hub.
	pub storage RequiredStakeForStakeAndSlash: Balance = 100 * constants::currency::UNITS;
}
```

**File:** system-parachains/bridge-hubs/bridge-hub-kusama/src/bridge_to_polkadot_config.rs (L140-141)
```rust
	// see the `FEE_BOOST_PER_MESSAGE` constant to get the meaning of this value
	pub PriorityBoostPerMessage: u64 = 364_179_930_795_847;
```

**File:** system-parachains/bridge-hubs/bridge-hub-kusama/src/bridge_to_polkadot_config.rs (L240-245)
```rust
	type ForceOrigin = EnsureRoot<AccountId>;
	// We don't want to allow creating bridges for this instance with `LegacyLaneId`.
	type OpenBridgeOrigin = EnsureNever<Location>;
	// Converter aligned with `OpenBridgeOrigin`.
	type BridgeOriginAccountIdConverter =
		(ParentIsPreset<AccountId>, SiblingParachainConvertsVia<Sibling, AccountId>);
```

**File:** system-parachains/bridge-hubs/bridge-hub-kusama/src/bridge_to_polkadot_config.rs (L260-294)
```rust
/// Implementation of `bp_xcm_bridge_hub::LocalXcmChannelManager` for congestion management.
pub struct CongestionManager;
impl pallet_xcm_bridge_hub::LocalXcmChannelManager for CongestionManager {
	type Error = SendError;

	fn is_congested(with: &Location) -> bool {
		// This is used to check the inbound bridge queue/messages to determine if they can be
		// dispatched and sent to the sibling parachain. Therefore, checking outbound `XcmpQueue`
		// is sufficient here.
		use bp_xcm_bridge_hub_router::XcmChannelStatusProvider;
		cumulus_pallet_xcmp_queue::bridging::OutXcmpChannelStatusProvider::<Runtime>::is_congested(
			with,
		)
	}

	fn suspend_bridge(local_origin: &Location, bridge: BridgeId) -> Result<(), Self::Error> {
		// This bridge is intended for AH<>AH communication with a hard-coded/static lane,
		// so `local_origin` is expected to represent only the local AH.
		send_xcm::<XcmpQueue>(
			local_origin.clone(),
			bp_asset_hub_kusama::build_congestion_message(bridge.inner(), true).into(),
		)
		.map(|_| ())
	}

	fn resume_bridge(local_origin: &Location, bridge: BridgeId) -> Result<(), Self::Error> {
		// This bridge is intended for AH<>AH communication with a hard-coded/static lane,
		// so `local_origin` is expected to represent only the local AH.
		send_xcm::<XcmpQueue>(
			local_origin.clone(),
			bp_asset_hub_kusama::build_congestion_message(bridge.inner(), false).into(),
		)
		.map(|_| ())
	}
}
```
