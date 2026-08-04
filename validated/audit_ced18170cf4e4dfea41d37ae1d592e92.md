### Title
Unprivileged Asset Hub account can spoof `snowbridge_pallet_system_v2` `FrontendOrigin` via a crafted `DescendOrigin` + `Transact` XCM sent through `pallet_xcm::send` - (File: system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs)

### Summary
`AllowFromEthereumFrontend::contains` only checks the *shape* of the origin `Location` (`(1, [Parachain(ASSET_HUB_ID), PalletInstance(SystemFrontendPalletInstance)])`), not who actually produced it. [1](#0-0)  Because Asset Hub allows any signed account to call `pallet_xcm::send` with an arbitrary XCM program, and BridgeHub's `OriginConverter` falls back to `XcmPassthrough` for any location it doesn't recognize natively, a normal signed AssetHub user can embed `DescendOrigin(PalletInstance(SystemFrontendPalletInstance))` in a message sent to BridgeHub and have it accepted as the genuine frontend pallet's origin.

### Finding Description
On Asset Hub Polkadot, `pallet_xcm::Config::SendXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalPalletOrSignedOriginToLocation>`, explicitly documented "Any local signed origin can send XCM messages." [2](#0-1)  `pallet_xcm::send` forwards the caller-supplied `VersionedXcm` program verbatim through `XcmRouter`/HRMP; it does not sanitize or restrict the instructions inside the message (only the invoking origin, not the message content, is checked).

On Bridge Hub Polkadot, the HRMP transport authenticates only that the message physically arrived from Parachain(ASSET_HUB_ID); it does not authenticate which pallet/account inside Asset Hub authored it. The message's leading `DescendOrigin` instruction is processed by the XCM executor and mutates the working origin from `(1, [Parachain(ASSET_HUB_ID)])` to `(1, [Parachain(ASSET_HUB_ID), PalletInstance(X)])`. When the subsequent `Transact` is dispatched, `OriginConverter = XcmOriginToTransactDispatchOrigin` is applied:
- `SovereignSignedViaLocation`, `RelayChainAsNative`, `SiblingParachainAsNative`, `LocationAsSuperuser<(RelayChainLocation, AssetHubLocation)>`, and `SignedAccountId32AsNative` all require exact-shape matches (bare `Parachain(id)`, or `AccountId32` junctions) and do not match a location with an extra `PalletInstance` junction.
- The final fallback, `XcmPassthrough<RuntimeOrigin>`, unconditionally converts *any* remaining location into `pallet_xcm::Origin::Xcm(location)`. [3](#0-2) 

The resulting origin is exactly `pallet_xcm::Origin::Xcm((1, [Parachain(ASSET_HUB_ID), PalletInstance(SystemFrontendPalletInstance::get())]))`, which is precisely what `AllowFromEthereumFrontend::contains` and therefore `EnsureXcm<AllowFromEthereumFrontend>` (`snowbridge_pallet_system_v2::Config::FrontendOrigin`) accept. [4](#0-3)  Because the Barrier's `AllowExplicitUnpaidExecutionFrom<(..., Equals<SnowbridgeFrontendLocation>), ...>` also matches this same computed origin, [5](#0-4)  the message is admitted for free execution, and the attacker only needs to prepend an `UnpaidExecution` instruction (or pay for weight via `BuyExecution`) to satisfy the barrier, then dispatch the `Transact` targeting a privileged `snowbridge_pallet_system_v2` call.

No check in this path verifies that the entity issuing `DescendOrigin`/`send` on Asset Hub is actually `snowbridge_pallet_system_frontend`; any signed Asset Hub account can produce the identical origin.

### Impact Explanation
An unprivileged, ordinary signed account on Asset Hub can invoke privileged `snowbridge_pallet_system_v2` extrinsics gated by `FrontendOrigin` (e.g., channel registration or pricing-parameter mutation) on Bridge Hub, without ever going through the real `snowbridge_pallet_system_frontend` pallet's authorization logic (`RegisterTokenOrigin`, asset-ownership checks, etc. defined in the Asset Hub's `snowbridge_pallet_system_frontend::Config`). [6](#0-5)  This is an unauthorized privileged configuration change to the Ethereum bridge's system parameters, matching the scoped impact of enabling later theft/freeze of bridged funds.

### Likelihood Explanation
Feasible with only a funded signed account on Asset Hub (no elevated privilege required) and knowledge of `SystemFrontendPalletInstance` (a public runtime constant). The attack is fully repeatable and requires no race condition, timing, or relayer collusion — it is a pure XCM-construction exploit reachable through the standard `pallet_xcm::send` extrinsic.

Caveat: exact runtime behavior of `xcm-builder`'s `AllowExplicitUnpaidExecutionFrom`, `WithComputedOrigin`, and `SiblingParachainAsNative`/`Equals` matching semantics is defined in the external `polkadot-sdk` crate, not in this repository, so I could not directly inspect their source to confirm edge-case behavior (e.g., whether these converters permit exact-length-only matches). This analysis relies on their well-documented, standard semantics used consistently across all runtimes in this repo.

### Recommendation
Do not gate `snowbridge_pallet_system_v2::Config::FrontendOrigin` purely on the resulting `Location` shape. Instead, restrict which locations are permitted to reach BridgeHub with a `DescendOrigin` to `PalletInstance(SystemFrontendPalletInstance)` — e.g., via `Aliasers`/barrier configuration that only allows this specific origin-descent when combined with pallet-of-origin proof, or require Asset Hub to route frontend-privileged calls only through an XCM mechanism the ordinary `pallet_xcm::send` path cannot forge (such as restricting `SendXcmOrigin`/`XcmExecuteFilter` on Asset Hub so arbitrary signed accounts cannot embed `DescendOrigin(PalletInstance(..))` into user-submitted messages, or filtering outbound messages at the Asset Hub XCM executor/router to strip/deny `DescendOrigin` instructions not issued by the actual `snowbridge_pallet_system_frontend` pallet's internal dispatch).

### Proof of Concept
xcm-emulator integration test:
1. On AssetHubPolkadot, as a plain signed account `alice` (not the system-frontend pallet), call `PolkadotXcm::send` targeting `BridgeHubPolkadot`, with message:
   `Xcm(vec![DescendOrigin(X1(PalletInstance(SystemFrontendPalletInstance::get()))), UnpaidExecution { weight_limit: Unlimited, check_origin: None }, Transact { origin_kind: OriginKind::Xcm, call: <EthereumSystemV2 privileged call>.encode() }])`.
2. On BridgeHubPolkadot, assert the `Transact`'d call succeeds and its event is emitted (e.g., pricing-parameter changed / channel registered), proving `EnsureXcm<AllowFromEthereumFrontend>` accepted an origin that did not originate from `snowbridge_pallet_system_frontend`.
3. Assert `AllowFromEthereumFrontend::contains(&Location::new(1, [Parachain(ASSET_HUB_ID), PalletInstance(SystemFrontendPalletInstance::get())]))` returns `true` regardless of the sender's identity within Asset Hub, confirming the filter cannot distinguish the real frontend pallet from a spoofing user account.

### Citations

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

**File:** system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs (L612-618)
```rust
impl pallet_xcm::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	// Any local signed origin can send XCM messages.
	type SendXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalPalletOrSignedOriginToLocation>;
	type XcmRouter = XcmRouter;
	// Any local signed origin can execute XCM messages.
	type ExecuteXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalSignedOriginToLocation>;
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

**File:** system-parachains/bridge-hubs/bridge-hub-polkadot/src/xcm_config.rs (L166-183)
```rust
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
```

**File:** system-parachains/asset-hubs/asset-hub-polkadot/src/bridge_to_ethereum_config.rs (L45-71)
```rust
impl snowbridge_pallet_system_frontend::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = weights::snowbridge_pallet_system_frontend::WeightInfo<Runtime>;
	#[cfg(feature = "runtime-benchmarks")]
	type Helper = ();
	type RegisterTokenOrigin = EitherOf<
		EitherOf<
			LocalAssetOwner<
				AssetIdForTrustBackedAssetsConvert<TrustBackedAssetsPalletLocation, Location>,
				Assets,
				AccountId,
				AssetIdForTrustBackedAssets,
				Location,
			>,
			ForeignAssetOwner<
				(
					FromSiblingParachain<parachain_info::Pallet<Runtime>, Location>,
					xcm_config::bridging::to_kusama::KusamaAssetFromAssetHubKusama,
				),
				ForeignAssets,
				AccountId,
				LocationToAccountId,
				Location,
			>,
		>,
		EnsureRootWithSuccess<AccountId, RootLocation>,
	>;
```
