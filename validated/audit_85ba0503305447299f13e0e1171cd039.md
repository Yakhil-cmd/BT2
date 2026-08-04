### Title
Unauthorized privileged `EthereumSystemFrontend` call via forged `EnsureXcm<AllowFromEthereumFrontend>` origin using `DescendOrigin` spoofing - (File: system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs)

### Summary
`FrontendOrigin` on `snowbridge_pallet_system_v2::Config` is `EnsureXcm<AllowFromEthereumFrontend>`, and `AllowFromEthereumFrontend` authenticates the caller purely by matching the *XCM location value* `(1, [Parachain(ASSET_HUB_ID), PalletInstance(SystemFrontendPalletInstance)])`, with no cryptographic binding to the genuine `SnowbridgeSystemFrontend` pallet's dispatch path. [1](#0-0)  Because Asset Hub Polkadot's `pallet_xcm::Config::SendXcmOrigin` allows any signed account to call `send`/`execute` with arbitrary, user-authored message bodies, and because Asset Hub's `LocalPalletOrSignedOriginToLocation` does not restrict message *content* (only who may invoke `send`), a normal signed user can author a raw XCM program containing `DescendOrigin(PalletInstance(SystemFrontendPalletInstance))` followed by `Transact{...}` and route it to BridgeHub. [2](#0-1) 

### Finding Description
On BridgeHub, inbound XCMP messages from a sibling parachain are processed with a "physical" starting origin of `Location::new(1, [Parachain(sender_para_id)])`, established by the transport layer, not by the identity of the account that authored the message on the sending chain. BridgeHub's `Barrier` is `WithComputedOrigin<..., UniversalLocation, ConstU32<8>>`, which peels leading `DescendOrigin`/`UniversalOrigin` instructions to compute an effective origin before evaluating the inner barrier tuple. [3](#0-2)  The inner barrier explicitly grants free/unpaid execution to `Equals<SnowbridgeFrontendLocation>`, where `SnowbridgeFrontendLocation = Location::new(1, [Parachain(ASSET_HUB_ID), PalletInstance(SystemFrontendPalletInstance)])` — a value derived entirely from a **public constant**. [4](#0-3) 

Because `DescendOrigin` is a standard, unrestricted XCM instruction that any message author can include, a signed Asset Hub user can craft `Xcm[DescendOrigin(PalletInstance(SystemFrontendPalletInstance)), Transact{ call: EthereumSystemFrontend::register_token(...) }]` and send it via `pallet_xcm::send` (or via `PausableExporter`/`XcmRouter` paths reachable from a signed user) to BridgeHub. On execution, the computed origin becomes `Location::new(1, [Parachain(ASSET_HUB_ID), PalletInstance(SystemFrontendPalletInstance)])` — indistinguishable from the location the genuine `SnowbridgeSystemFrontend` pallet would produce. `Transact` then converts this via `XcmOriginToTransactDispatchOrigin`'s `XcmPassthrough<RuntimeOrigin>` fallback into `pallet_xcm::Origin::Xcm(location)`. [5](#0-4)  `EnsureXcm<AllowFromEthereumFrontend>` only checks the location pattern, which now matches, so `BadOrigin` is never raised and the privileged call dispatches. [1](#0-0) 

None of the existing protections stop this:
- Asset Hub's `SendXcmOrigin`/`ExecuteXcmOrigin` restrict *who* may call `send`/`execute`, not the message *content* (i.e., which `DescendOrigin` junctions may be embedded). [2](#0-1) 
- BridgeHub's `SafeCallFilter = Everything` does not block the Transact call. [6](#0-5) 
- `AllowFromEthereumFrontend` is a pure `Contains<Location>` structural match with no additional proof-of-authenticity (e.g., no `Aliasers`/`AuthorizedAliasers`-based check requiring explicit permission to represent that sub-location). [7](#0-6) 

### Impact Explanation
An unprivileged Asset Hub signed account can directly invoke `FrontendOrigin`-gated calls on `snowbridge_pallet_system_v2` on BridgeHub (e.g. token registration / Ethereum gateway configuration calls), bypassing all business logic, fee/deposit requirements, and permission checks normally enforced inside the real `SnowbridgeSystemFrontend` pallet on Asset Hub. This enables unauthorized asset registration or gateway configuration drift on the Ethereum bridge system, which can be leveraged as a precursor to asset-accounting corruption or theft via subsequent bridge transfers of the maliciously registered/misconfigured asset.

### Likelihood Explanation
Fully feasible and repeatable with only public information: `SystemFrontendPalletInstance` is a public runtime constant, `pallet_xcm::send` is callable by any signed account on Asset Hub Polkadot, and `DescendOrigin` + `Transact` are standard, unrestricted XCM instructions available to any message author. No governance, root, or leaked-key access is required — only a funded signed account able to

### Citations

**File:** system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs (L82-82)
```rust
	pub SnowbridgeFrontendLocation: Location = Location::new(1, [Parachain(polkadot_runtime_constants::system_parachain::ASSET_HUB_ID), PalletInstance(SystemFrontendPalletInstance::get())]);
```

**File:** system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs (L292-313)
```rust
pub struct AllowFromEthereumFrontend;
impl Contains<Location> for AllowFromEthereumFrontend {
	fn contains(location: &Location) -> bool {
		match location.unpack() {
			(1, [Parachain(para_id), PalletInstance(index)]) =>
				*para_id == polkadot_runtime_constants::system_parachain::ASSET_HUB_ID &&
					*index == SystemFrontendPalletInstance::get(),
			_ => false,
		}
	}
}

impl snowbridge_pallet_system_v2::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type OutboundQueue = EthereumOutboundQueueV2;
	type InboundQueue = EthereumInboundQueueV2;
	type FrontendOrigin = EnsureXcm<AllowFromEthereumFrontend>;
	type WeightInfo = crate::weights::snowbridge_pallet_system_v2::WeightInfo<Runtime>;
	type GovernanceOrigin = EnsureRootWithSuccess<crate::AccountId, RootLocation>;
	#[cfg(feature = "runtime-benchmarks")]
	type Helper = ();
}
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

**File:** system-parachains/bridge-hubs/bridge-hub-polkadot/src/xcm_config.rs (L120-139)
```rust
pub type XcmOriginToTransactDispatchOrigin = (
	// Sovereign account converter; this attempts to derive an `AccountId` from the origin location
	// using `LocationToAccountId` and then turn that into the usual `Signed` origin. Useful for
	// foreign chains who want to have a local sovereign account on this chain which they control.
	SovereignSignedViaLocation<LocationToAccountId, RuntimeOrigin>,
	// Native converter for Relay-chain (Parent) location; will converts to a `Relay` origin when
	// recognized.
	RelayChainAsNative<RelayChainOrigin, RuntimeOrigin>,
	// Native converter for sibling Parachains; will convert to a `SiblingPara` origin when
	// recognized.
	SiblingParachainAsNative<cumulus_pallet_xcm::Origin, RuntimeOrigin>,
	// AssetHub or Relay can execute as root (based on: https://github.com/polkadot-fellows/runtimes/issues/651).
	// This will allow them to issue a transaction from the Root origin.
	LocationAsSuperuser<(Equals<RelayChainLocation>, Equals<AssetHubLocation>), RuntimeOrigin>,
	// Native signed account converter; this just converts an `AccountId32` origin into a normal
	// `RuntimeOrigin::Signed` origin of the same 32-byte value.
	SignedAccountId32AsNative<RelayNetwork, RuntimeOrigin>,
	// Xcm origins can be represented natively under the Xcm pallet's Xcm origin.
	XcmPassthrough<RuntimeOrigin>,
);
```

**File:** system-parachains/bridge-hubs/bridge-hub-polkadot/src/xcm_config.rs (L150-194)
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
					// Parent, its pluralities (i.e. governance bodies), Fellows plurality
					// and relay treasury get free execution.
					AllowExplicitUnpaidExecutionFrom<
						(
							ParentOrParentsPlurality,
							FellowsPlurality,
							Equals<RelayTreasuryLocation>,
							Equals<AssetHubLocation>,
							AssetHubPlurality,
							Equals<SnowbridgeFrontendLocation>,
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

**File:** system-parachains/bridge-hubs/bridge-hub-polkadot/src/xcm_config.rs (L259-259)
```rust
	type SafeCallFilter = Everything;
```
