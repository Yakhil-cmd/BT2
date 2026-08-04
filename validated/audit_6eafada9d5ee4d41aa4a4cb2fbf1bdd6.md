#No

Vulnerability found for this question.

**Analysis basis:** `AllowSiblingsOnly` gates `snowbridge_pallet_system::Config::SiblingOrigin` (`EnsureXcm<AllowSiblingsOnly>`), which is only consulted when a parachain sends an XCM `Transact` to create/manage a channel/agent — i.e., at channel *registration* time, not at inbound message *submission* time. [1](#0-0) 

The inbound queue's `ChannelLookup = EthereumSystem` resolves a `channel_id` against storage populated only through that privileged/sibling-authenticated registration flow, not from attacker-supplied hashing at submit time. [2](#0-1) 

The premise conflates two independent mechanisms: `ChannelLookup` (a storage lookup keyed by a previously-registered `channel_id`) and `AllowSiblingsOnly` (an XCM origin filter checked only at registration). A forged `channel_id`/`AgentId` in an inbound Ethereum message cannot "bypass" `AllowSiblingsOnly` because that filter is never invoked during `submit`; it is invoked only when a sibling parachain establishes a channel via genuine XCM transport (HRMP/UMP), whose origin cannot be spoofed by a signed extrinsic/proxy caller. Additionally, forging a `blake2_256`-based `AgentIdOf::convert_location` collision between a non-sibling and a sibling location is not a logic/type-confusion bug but would require breaking the hash function itself — outside the scope of a runtime logic flaw. Finally, actually getting a forged message accepted by `submit` still requires a valid Ethereum beacon/Merkle proof verified by `EthereumBeaconClient`, which is excluded per the rules against relying on impossible external-chain assumptions. [3](#0-2) 

No reachable Rust path exists where an unprivileged attacker's inbound-queue `submit` call can cause `ChannelLookup` to resolve to a sibling's channel without that sibling having genuinely registered it through the `AllowSiblingsOnly`-gated origin check.

### Citations

**File:** system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs (L57-64)
```rust
/// Exports message to the Ethereum Gateway contract.
pub type SnowbridgeExporter = EthereumBlobExporter<
	UniversalLocation,
	EthereumNetwork,
	snowbridge_pallet_outbound_queue::Pallet<Runtime>,
	snowbridge_core::AgentIdOf,
	EthereumSystem,
>;
```

**File:** system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs (L92-120)
```rust
impl snowbridge_pallet_inbound_queue::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Verifier = snowbridge_pallet_ethereum_client::Pallet<Runtime>;
	type Token = Balances;
	#[cfg(not(feature = "runtime-benchmarks"))]
	type XcmSender = xcm_config::XcmRouter;
	#[cfg(feature = "runtime-benchmarks")]
	type XcmSender = benchmark_helpers::DoNothingRouter;
	type ChannelLookup = EthereumSystem;
	type GatewayAddress = EthereumGatewayAddress;
	#[cfg(feature = "runtime-benchmarks")]
	type Helper = Runtime;
	type MessageConverter = MessageToXcm<
		CreateAssetCallIndex,
		bp_asset_hub_polkadot::CreateForeignAssetDeposit,
		InboundQueuePalletInstance,
		AccountId,
		Balance,
		EthereumSystem,
		EthereumUniversalLocation,
		AssetHubFromEthereum,
	>;
	type WeightToFee = WeightToFee<Self>;
	type LengthToFee = ConstantMultiplier<Balance, TransactionByteFee>;
	type MaxMessageSize = ConstU32<2048>;
	type WeightInfo = crate::weights::snowbridge_pallet_inbound_queue::WeightInfo<Runtime>;
	type PricingParameters = EthereumSystem;
	type AssetTransactor = <xcm_config::XcmConfig as xcm_executor::Config>::AssetTransactor;
}
```

**File:** system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs (L276-290)
```rust
impl snowbridge_pallet_system::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type OutboundQueue = EthereumOutboundQueue;
	type SiblingOrigin = EnsureXcm<AllowSiblingsOnly>;
	type AgentIdOf = snowbridge_core::AgentIdOf;
	type TreasuryAccount = RelayTreasuryPalletAccount;
	type Token = Balances;
	type WeightInfo = crate::weights::snowbridge_pallet_system::WeightInfo<Runtime>;
	#[cfg(feature = "runtime-benchmarks")]
	type Helper = Runtime;
	type DefaultPricingParameters = Parameters;
	type InboundDeliveryCost = EthereumInboundQueue;
	type UniversalLocation = UniversalLocation;
	type EthereumLocation = EthereumLocation;
}
```
