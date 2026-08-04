### Title
Unrestricted `PolkadotXcm::send` + `DescendOrigin` allows any signed Asset Hub account to forge the `SnowbridgeFrontendLocation` origin and invoke privileged `EthereumSystemFrontend` calls on BridgeHub - (File: system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs)

### Summary
`snowbridge_pallet_system_v2::Config::FrontendOrigin = EnsureXcm<AllowFromEthereumFrontend>` only checks that the *converted* XCM origin location matches `(1, [Parachain(ASSET_HUB_ID), PalletInstance(SystemFrontendPalletInstance)])`, without any guarantee that this location was set by the genuine `SnowbridgeSystemFrontend` pallet rather than forged with a `DescendOrigin` instruction. Because Asset Hub's `pallet_xcm::Config::SendXcmOrigin` allows any signed account to call `send()` with an arbitrary XCM program, and BridgeHub's `Barrier`/`OriginConverter`/`SafeCallFilter` trust a `DescendOrigin`-computed origin equal to `SnowbridgeFrontendLocation`, a normal signed Asset Hub user can impersonate the frontend pallet and dispatch privileged calls such as `register_token` on BridgeHub.

### Finding Description
- On Asset Hub Polkadot, `pallet_xcm::Config::SendXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalPalletOrSignedOriginToLocation>` and the code comment states "Any local signed origin can send XCM messages." [1](#0-0)  `pallet_xcm::send` forwards the caller-supplied XCM program verbatim to the router with no content/instruction filtering.
- On BridgeHub Polkadot, incoming sibling XCMP messages are executed with a base origin equal to the sending chain's location (Asset Hub, `Parachain(1000)`), and `WithComputedOrigin` processes leading `DescendOrigin` instructions to compute an effective origin used both for the `Barrier` check and for the actual XCM VM origin register used by subsequent `Transact`. [2](#0-1) 
- The `Barrier`'s `AllowExplicitUnpaidExecutionFrom` list explicitly whitelists `Equals<SnowbridgeFrontendLocation>` for free/unpaid execution. [3](#0-2)  `SnowbridgeFrontendLocation` is defined as `(1, [Parachain(ASSET_HUB_ID), PalletInstance(SystemFrontendPalletInstance)])` — the same location that `AllowFromEthereumFrontend::contains` checks for. [4](#0-3) [5](#0-4) 
- `OriginConverter = XcmOriginToTransactDispatchOrigin` includes `XcmPassthrough<RuntimeOrigin>` as the fallback converter, turning any unmatched location into `RuntimeOrigin::from(pallet_xcm::Origin::Xcm(location))`. [6](#0-5)  This is exactly what `EnsureXcm<AllowFromEthereumFrontend>` accepts for `FrontendOrigin`. [7](#0-6) 
- `SafeCallFilter = Everything` on BridgeHub's `XcmConfig` means `Transact` can dispatch any call, with no allow-list restricting which pallets/calls may be reached this way. [8](#0-7) 

Exploit flow: attacker (signed Asset Hub account) calls `PolkadotXcm::send(dest = BridgeHub, message = Xcm[DescendOrigin(PalletInstance(SystemFrontendPalletInstance)), UnpaidExecution{...}, Transact{origin_kind: Xcm, call: EthereumSystemFrontend::register_token(...)}])`. The message queues via XCMP to BridgeHub with base transport origin `(1, Parachain(1000))`. On arrival, `DescendOrigin` (executed as a normal, unconditionally-honored instruction, not gated by `Aliasers`) appends `PalletInstance(SystemFrontendPalletInstance)`, producing an effective origin identical to `SnowbridgeFrontendLocation`. The `Barrier` permits unpaid execution because this computed origin is explicitly whitelisted. `Transact` then converts this origin via `XcmPassthrough` into `pallet_xcm::Origin::Xcm(SnowbridgeFrontendLocation)`, which satisfies `EnsureXcm<AllowFromEthereumFrontend>`, letting the dispatched call execute as `FrontendOrigin`.

None of the existing checks stop this: the Barrier only checks the *location value*, not provenance; `DescendOrigin` is unconditionally applied to any sibling-origin message; `SafeCallFilter = Everything` does not restrict reachable calls; and `AllowFromEthereumFrontend` performs pure location pattern-matching with no cryptographic or provenance binding to the real frontend pallet.

### Impact Explanation
An unprivileged Asset Hub account can directly invoke privileged `snowbridge_pallet_system_v2` calls gated by `FrontendOrigin` (e.g., token registration / gateway configuration calls) on BridgeHub, bypassing whatever authorization/deposit logic the genuine `SnowbridgeSystemFrontend` pallet on Asset Hub enforces. This causes unauthorized asset registration / bridge configuration drift, which can be leveraged for downstream asset confusion or theft via the Ethereum bridge.

### Likelihood Explanation
Fully feasible and repeatable by any signed Asset Hub account with funds to pay XCMP delivery costs. Preconditions (knowledge of the public `SystemFrontendPalletInstance` constant, ability to call `PolkadotXcm::send`) are trivially met since these are public runtime constants and `send()` is explicitly open to "any local signed origin."

### Recommendation
Do not trust a bare location-pattern match for privileged frontend calls. Either: (1) restrict Asset Hub's outgoing XCM (`SendXcmOrigin`/`SafeCallFilter`/a dedicated router) so ordinary signed accounts cannot embed `DescendOrigin` claiming pallet-instance junctions; (2) on BridgeHub, remove `Equals<SnowbridgeFrontendLocation>` from the unpaid-execution allow-list and/or restrict `SafeCallFilter` so `Transact` cannot reach `EthereumSystemFrontend`/`snowbridge_pallet_system_v2` privileged extrinsics from computed (`DescendOrigin`-derived) origins; (3) use a provenance-bound mechanism (e.g., `AliasOrigin`+`Aliasers` authorization list, or a dedicated signed/verified channel) instead of relying purely on `EnsureXcm<AllowFromEthereumFrontend>` location matching for `FrontendOrigin`.

### Proof of Concept
xcm-emulator test:
1. On Asset Hub Polkadot emulated chain, fund a plain signed `attacker` account.
2. Call `AssetHubPolkadot::execute_with(|| PolkadotXcm::send(RuntimeOrigin::signed(attacker), Box::new(VersionedLocation::from(BridgeHubLocation)), Box::new(VersionedXcm::from(Xcm(vec![DescendOrigin(PalletInstance(SystemFrontendPalletInstance::get()).into()), UnpaidExecution{weight_limit: Unlimited, check_origin: None}, Transact{origin_kind: OriginKind::Xcm, call: register_token_call.encode().into(), ..}])))))`.
3. Process the message on BridgeHub Polkadot emulated chain.
4. Assert that the `register_token` (or equivalent `EthereumSystemFrontend`) call succeeded / emitted its success event, proving `FrontendOrigin` was satisfied despite the origin not truly coming from `SnowbridgeSystemFrontend`.
5. Contrast with expected-secure behavior: assert should instead show `BadOrigin`/rejection if the fix (restricting `SendXcmOrigin`, `SafeCallFilter`, or Barrier trust) is applied.

### Citations

**File:** system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs (L612-619)
```rust
impl pallet_xcm::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	// Any local signed origin can send XCM messages.
	type SendXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalPalletOrSignedOriginToLocation>;
	type XcmRouter = XcmRouter;
	// Any local signed origin can execute XCM messages.
	type ExecuteXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalSignedOriginToLocation>;
	type XcmExecuteFilter = Everything;
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

**File:** system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs (L82-82)
```rust
	pub SnowbridgeFrontendLocation: Location = Location::new(1, [Parachain(polkadot_runtime_constants::system_parachain::ASSET_HUB_ID), PalletInstance(SystemFrontendPalletInstance::get())]);
```

**File:** system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs (L292-302)
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
```

**File:** system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs (L304-313)
```rust
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
