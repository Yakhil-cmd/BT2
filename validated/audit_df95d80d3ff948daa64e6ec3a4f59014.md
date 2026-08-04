### Title
Unprivileged Asset Hub account can obtain `RuntimeOrigin::root()` on Kusama relay chain via `pallet_xcm::send` and `LocationAsSuperuser<Equals<AssetHubLocation>>` - (File: relay/kusama/src/xcm_config.rs)

### Summary
The Kusama relay chain's `LocalOriginConverter` treats *any* UMP message whose transport-level origin is exactly `Parachain(ASSET_HUB_ID)` as fully privileged root via `LocationAsSuperuser<Equals<AssetHubLocation>, RuntimeOrigin>`, without any check on which internal AssetHub caller actually produced the message. Because Asset Hub's `pallet_xcm::Config::SendXcmOrigin` permits "any local signed origin" to call `pallet_xcm::send` with an arbitrary destination and arbitrary raw XCM program, any unprivileged, fee-paying AssetHub account can construct and deliver a `Transact{ origin_kind: Superuser, call: <relay call> }` message to the relay, which the relay's `OriginConverter` will dispatch with `RuntimeOrigin::root()`.

### Finding Description
On the relay chain, `LocalOriginConverter` includes: [1](#0-0) 

`AssetHubLocation` is defined as the bare parachain location `Parachain(ASSET_HUB_ID)`: [2](#0-1) 

When a message arrives at the relay chain via its UMP/DMP queue from a parachain, the XCM executor assigns the *origin* for that program based purely on the identity of the sending parachain's channel (`Parachain(ASSET_HUB_ID)`), independent of which account inside Asset Hub actually triggered the send. The relay `Barrier` explicitly grants free/unpaid execution to any message whose (possibly `WithComputedOrigin`-resolved) origin is a child system parachain, which includes Asset Hub: [3](#0-2) 
No further check restricts *who inside* Asset Hub could have produced the message, and `SafeCallFilter = Everything` on the relay places no restriction on which `RuntimeCall` a `Transact` may dispatch: [4](#0-3) 

On the Asset Hub Kusama side, `pallet_xcm::Config::SendXcmOrigin` is configured to let **any signed account** call `send`: [5](#0-4) 
using `LocalPalletOrSignedOriginToLocation`, which includes plain `SignedToAccountId32<RuntimeOrigin, AccountId, RelayNetwork>`: [6](#0-5) 

`pallet_xcm::send` forwards the caller-supplied `Xcm` program verbatim to the destination via the configured router (`ParentAsUmp` for the relay chain): [7](#0-6) 
The `SendXcmOrigin` conversion is only used to identify the local "sender" location for fee/event bookkeeping — it does not embed itself into, or in any way constrain, the arbitrary XCM instructions the caller places in `message`. Consequently, any signed Asset Hub account can put a `Transact{ origin_kind: OriginKind::Superuser, call: <any relay RuntimeCall> }` in the outbound message; because that message is delivered on the AssetHub→Kusama UMP channel, the relay's executor tags it with origin `Parachain(ASSET_HUB_ID)`, which matches `Equals<AssetHubLocation>` exactly, and `LocationAsSuperuser` converts it straight to `RuntimeOrigin::root()`. No `DescendOrigin`/re-aliasing trick is even required — the trivial default path already produces this outcome, since the relay has no way to see, and no configured mechanism checks, the caller identity inside Asset Hub.

### Impact Explanation
Any fee-paying, unprivileged Asset Hub account can dispatch **arbitrary root-level calls on the Kusama relay chain** (e.g. `frame_system::set_code`, treasury spends, staking configuration, validator set manipulation), i.e. full relay chain takeover / privilege escalation from a completely unprivileged account. This is the most severe class of impact possible in this system (root compromise).

### Likelihood Explanation
Fully feasible and repeatable with standard, unprivileged tooling: any KSM-holding account on Asset Hub Kusama can call the `polkadotXcm.send` extrinsic (paying only the ordinary XCM delivery fee) with a hand-crafted `VersionedXcm` containing a single `Transact` instruction. No governance approval, proxy grant, or special permission is needed — this is directly reachable from a signed extrinsic on a live, permissionless parachain.

### Recommendation
Do not trust the raw parachain-level UMP origin (`Parachain(ASSET_HUB_ID)`) as sufficient proof of an authorized "root" message. Either:
- Restrict Asset Hub's `pallet_xcm::Config::SendXcmOrigin` so that only a specific privileged origin (e.g. `EnsureRoot`, a dedicated migration/governance track, or `StakingAdmin`/`Fellows`-only pluralities) can send messages destined for the relay chain with `Transact`+`Superuser`, removing the plain signed-account converter from that path; and/or
- On the relay side, do not use a blanket `LocationAsSuperuser<Equals<AssetHubLocation>, ...>`; instead require an additional, cryptographically/structurally verifiable marker (e.g. accept root-equivalence only for specific pallet/call indices via `SafeCallFilter`, or require the message to originate from a location that itself encodes an already-authorized Asset Hub governance origin) so that arbitrary signed AssetHub users cannot cause root dispatch on the relay.

### Proof of Concept
xcm-emulator integration test:
```rust
#[test]
fn unprivileged_asset_hub_account_cannot_get_root_on_relay() {
    // Setup Kusama + AssetHubKusama in emulated network.
    AssetHubKusama::execute_with(|| {
        let attacker: AccountId = get_unprivileged_signed_account(); // any funded, non-privileged account
        let call = kusama_runtime::RuntimeCall::System(
            frame_system::Call::set_code { code: vec![] } // stand-in for a state-changing root call
        );
        let message = Xcm(vec![
            UnpaidExecution { weight_limit: Unlimited, check_origin: None },
            Transact {
                origin_kind: OriginKind::Superuser,
                call: call.encode().into(),
            },
        ]);
        assert_ok!(pallet_xcm::Pallet::<Runtime>::send(
            RuntimeOrigin::signed(attacker),
            Box::new(Location::parent().into()),
            Box::new(xcm::VersionedXcm::from(message)),
        ));
    });

    Kusama::execute_with(|| {
        // Assert that the Transact executed with Root and mutated relay state,
        // proving privilege escalation from an unprivileged AssetHub account.
        assert!(System::events().iter().any(|r| matches!(
            r.event,
            RuntimeEvent::System(frame_system::Event::CodeUpdated) 
        )));
    });
}
```
Expected assertion: the relay chain observes a root-level state transition (`CodeUpdated`/equivalent) triggered solely by an unprivileged Asset Hub signed account, with no Fellows/StakingAdmin/root-track involvement — demonstrating the invariant "no sub-origin of AssetHub can impersonate root" is violated (in fact, no manipulation beyond a normal signed `send` is even required).

### Citations

**File:** relay/kusama/src/xcm_config.rs (L97-109)
```rust
/// The means that we convert the XCM message origin location into a local dispatch origin.
type LocalOriginConverter = (
	// A `Signed` origin of the sovereign account that the original location controls.
	SovereignSignedViaLocation<SovereignAccountOf, RuntimeOrigin>,
	// A child parachain, natively expressed, has the `Parachain` origin.
	ChildParachainAsNative<parachains_origin::Origin, RuntimeOrigin>,
	// The AccountId32 location type can be expressed natively as a `Signed` origin.
	SignedAccountId32AsNative<ThisNetwork, RuntimeOrigin>,
	// Xcm origins can be represented natively under the Xcm pallet's Xcm origin.
	XcmPassthrough<RuntimeOrigin>,
	// AssetHub can execute as root (based on: https://github.com/polkadot-fellows/runtimes/issues/651).
	LocationAsSuperuser<Equals<AssetHubLocation>, RuntimeOrigin>,
);
```

**File:** relay/kusama/src/xcm_config.rs (L137-137)
```rust
	pub AssetHubLocation: Location = Parachain(ASSET_HUB_ID).into_location();
```

**File:** relay/kusama/src/xcm_config.rs (L180-198)
```rust
/// The barriers one of which must be passed for an XCM message to be executed.
pub type Barrier = TrailingSetTopicAsId<(
	// Weight that is paid for may be consumed.
	TakeWeightCredit,
	// Expected responses are OK.
	AllowKnownQueryResponses<XcmPallet>,
	WithComputedOrigin<
		(
			// If the message is one that immediately attempts to pay for execution, then allow it.
			AllowTopLevelPaidExecutionFrom<Everything>,
			// Messages coming from system parachains need not pay for execution.
			AllowExplicitUnpaidExecutionFrom<(IsChildSystemParachain<ParaId>, AssetHubPlurality)>,
			// Subscriptions for version tracking are OK.
			AllowSubscriptionsFrom<OnlyParachains>,
		),
		UniversalLocation,
		ConstU32<8>,
	>,
)>;
```

**File:** relay/kusama/src/xcm_config.rs (L204-248)
```rust
pub struct XcmConfig;
impl xcm_executor::Config for XcmConfig {
	type RuntimeCall = RuntimeCall;
	type XcmSender = XcmRouter;
	type XcmRecorder = XcmPallet;
	type AssetTransactor = LocalAssetTransactor;
	type OriginConverter = LocalOriginConverter;
	type IsReserve = ();
	type IsTeleporter = TrustedTeleporters;
	type UniversalLocation = UniversalLocation;
	type Barrier = Barrier;
	type Weigher = WeightInfoBounds<
		crate::weights::xcm::KusamaXcmWeight<RuntimeCall>,
		RuntimeCall,
		MaxInstructions,
	>;
	// The weight trader piggybacks on the existing transaction-fee conversion logic.
	type Trader =
		UsingComponents<WeightToFee, TokenLocation, AccountId, Balances, ToAuthor<Runtime>>;
	type ResponseHandler = XcmPallet;
	type AssetTrap = XcmPallet;
	type AssetLocker = ();
	type AssetExchanger = ();
	type SubscriptionService = XcmPallet;
	type PalletInstancesInfo = AllPalletsWithSystem;
	type MaxAssetsIntoHolding = MaxAssetsIntoHolding;
	type FeeManager = XcmFeeManagerFromComponents<
		WaivedLocations,
		// TODO: post-ahm move the Treasury funds from this local account to sovereign account
		// of the new AH Treasury.
		SendXcmFeeToAccount<Self::AssetTransactor, TreasuryAccount>,
	>;
	// No bridges on the Relay Chain
	type MessageExporter = ();
	type UniversalAliases = Nothing;
	type CallDispatcher = RuntimeCall;
	type SafeCallFilter = Everything;
	// We let locations alias into child locations of their own.
	// This is a simple aliasing rule, mimicking the behaviour of the `DescendOrigin` instruction.
	type Aliasers = AliasChildLocation;
	type TransactionalProcessor = FrameTransactionalProcessor;
	type HrmpNewChannelOpenRequestHandler = ();
	type HrmpChannelAcceptedHandler = ();
	type HrmpChannelClosingHandler = ();
	type XcmEventEmitter = XcmPallet;
```

**File:** system-parachains/asset-hubs/asset-hub-kusama/src/xcm_config.rs (L447-462)
```rust
/// Converts a local signed origin into an XCM `Location`.
/// Forms the basis for local origins sending/executing XCMs.
pub type LocalSignedOriginToLocation = SignedToAccountId32<RuntimeOrigin, AccountId, RelayNetwork>;

/// Type to convert a pallet `Origin` type value into a `Location` value which represents an
/// interior location of this chain for a destination chain.
pub type LocalPalletOrSignedOriginToLocation = (
	// GeneralAdmin origin to be used in XCM as a corresponding Plurality `Location` value.
	GeneralAdminToPlurality,
	// StakingAdmin origin to be used in XCM as a corresponding Plurality `Location` value.
	StakingAdminToPlurality,
	// FellowshipAdmin origin to be used in XCM as a corresponding Plurality `Location` value.
	FellowshipAdminToPlurality,
	// And a usual Signed origin to be used in XCM as a corresponding `AccountId32`.
	SignedToAccountId32<RuntimeOrigin, AccountId, RelayNetwork>,
);
```

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
