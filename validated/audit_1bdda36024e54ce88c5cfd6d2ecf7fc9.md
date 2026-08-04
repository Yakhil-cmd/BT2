### Title
Any signed AssetHub account can forge Root-equivalent `AliasOrigin` into arbitrary Bulletin identities via `AliasOriginRootUsingFilter<AssetHubLocation, Everything>` - ([File: system-parachains/bulletin/bulletin-polkadot/src/xcm_config.rs])

### Summary
`TrustedAliasers` on Bulletin trusts *any* message whose XCM origin resolves to `AssetHubLocation` to alias into *any* target location (`AliasOriginRootUsingFilter<AssetHubLocation, Everything>`), but that origin is assigned purely by the XCMP transport layer based on the sending parachain's identity — not by which account on AssetHub triggered the send. Since AssetHub's `pallet_xcm::Config::SendXcmOrigin` explicitly permits any signed account to call `send()` with an arbitrary raw XCM program, an unprivileged AssetHub user can directly craft and send an `AliasOrigin` (or `Transact{origin_kind: Superuser}`) instruction to Bulletin that is indistinguishable, at the Bulletin executor, from a message issued by AssetHub's own governance/Root.

### Finding Description
Bulletin's aliasing configuration is: [1](#0-0) 

`AliasOriginRootUsingFilter<AssetHubLocation, Everything>` means: if the incoming XCM message's *origin location* equals `AssetHubLocation`, the `AliasOrigin` instruction is allowed to alias into **any** `Location` (filter = `Everything`), completely bypassing `AliasAccountId32FromSiblingSystemChain`'s same-account restriction.

The origin location seen by the Bulletin XCM executor for an inbound XCMP message is determined solely by the sending parachain's identity as recorded by the channel/queue (i.e. it is always tagged `Location::new(1, [Parachain(AssetHub_ID)])`), regardless of which account inside AssetHub queued the message. This is confirmed by the symmetric pattern used across the codebase, e.g. `LocationAsSuperuser<(Equals<RelayChainLocation>, Equals<AssetHubLocation>), RuntimeOrigin>`: [2](#0-1) 

On AssetHub itself, `pallet_xcm::Config::SendXcmOrigin` is deliberately opened to any signed account: [3](#0-2) 

`LocalPalletOrSignedOriginToLocation` includes `SignedToAccountId32<RuntimeOrigin, AccountId, RelayNetwork>`, and the accompanying comment confirms "Any local signed origin can send XCM messages." `pallet_xcm::send` forwards the caller-supplied `Xcm<()>` program verbatim to the router; it does not restrict instruction content (no filtering of `AliasOrigin`/`Transact` fields), and does not prepend a `DescendOrigin` reflecting the caller's sub-identity.

Consequently, a plain signed AssetHub account can call:
```
PolkadotXcm::send(
  RuntimeOrigin::signed(attacker),
  dest = Bulletin,
  message = Xcm([UnpaidExecution{..}, AliasOrigin(victim_bulletin_location), ...])
)
```
When this message is delivered to Bulletin via XCMP, the executor's origin register is `AssetHubLocation` (set by the transport layer, not the message content), so `AliasOriginRootUsingFilter<AssetHubLocation, Everything>` grants aliasing into `victim_bulletin_location` — any account, not just ones satisfying `AliasAccountId32FromSiblingSystemChain`. Bulletin's `Barrier` also explicitly allows unpaid execution from `AssetHubLocation`, so no fee token is even required: [4](#0-3) 

None of the existing checks stop this: `AliasChildLocation` and `AliasAccountId32FromSiblingSystemChain` are irrelevant since `AliasOriginRootUsingFilter` is evaluated independently and matches first on origin equality; the `Barrier` permits unpaid execution from `Equals<GovernanceLocation>` (= `AssetHubLocation`); and the `OriginConverter`/aliaser logic has no way to distinguish "AssetHub governance sent this" from "an AssetHub signed user sent this," because both produce the identical wire-level origin.

### Impact Explanation
Any signed AssetHub account can impersonate an arbitrary Bulletin-chain identity/account (via `AliasOrigin`) or, more broadly, obtain a `RuntimeOrigin::root()`-equivalent dispatch on Bulletin (via `Transact{origin_kind: Superuser}` through the identically-scoped `LocationAsSuperuser<..., Equals<AssetHubLocation>>` origin converter). This breaks the invariant that only genuine AssetHub Root/governance may alias into arbitrary Bulletin identities, and effectively grants unprivileged users full control of the Bulletin chain (identity spoofing, arbitrary privileged calls, storage/notary manipulation).

### Likelihood Explanation
Fully feasible and repeatable: the attacker only needs a funded signed AssetHub account (no governance, no special role) and knowledge of the target Bulletin location/account. AssetHub's `SendXcmOrigin` is explicitly configured to allow any signed account to call `pallet_xcm::send` with an arbitrary program, and the delivery path (XCMP AssetHub → Bulletin sibling channel) is a standard, always-open system-parachain channel.

### Recommendation
Do not trust the raw sending-parachain location as a stand-in for "AssetHub Root/governance." Either:
- Restrict `AssetHubLocation`'s ability to reach `LocationAsSuperuser`/`AliasOriginRootUsingFilter` to messages that carry a specific plurality/origin marker only producible by AssetHub governance (e.g., require the message to originate from a `GeneralAdmin`/governance-derived Plurality location on AssetHub rather than the bare sibling-parachain location), or
- Restrict AssetHub's own `SendXcmOrigin` so that plain signed accounts cannot freely queue arbitrary `Transact`/`AliasOrigin` XCM instructions to other system chains, or
- Replace `AliasOriginRootUsingFilter<AssetHubLocation, Everything>` with a filter that only allows aliasing into locations explicitly pre-authorized (mirroring `AuthorizedAliasers`), removing the blanket `Everything` trust.

### Proof of Concept
xcm-emulator test (pattern following existing `send.rs` / `governance.rs` tests in this repo):
```rust
#[test]
fn signed_asset_hub_account_can_alias_or_root_into_bulletin() {
    let attacker = AssetHubPolkadot::account_id_of(ALICE); // ordinary funded signed account
    let victim_bulletin_location: Location = /* some third-party Bulletin AccountId32 location */;

    AssetHubPolkadot::execute_with(|| {
        let xcm = Xcm(vec![
            UnpaidExecution { weight_limit: Unlimited, check_origin: None },
            AliasOrigin(victim_bulletin_location.clone()),
            // or: Transact { origin_kind: OriginKind::Superuser, call: <root-only call>.encode().into(), .. }
        ]);
        assert_ok!(<AssetHubPolkadot as AssetHubPolkadotPallet>::PolkadotXcm::send(
            <AssetHubPolkadot as Chain>::RuntimeOrigin::signed(attacker),
            bx!(VersionedLocation::from(AssetHubPolkadot::sibling_location_of(BulletinPolkadot::para_id()))),
            bx!(VersionedXcm::from(xcm)),
        ));
    });

    BulletinPolkadot::execute_with(|| {
        // Assert the AliasOrigin succeeded / Transact executed with Root — i.e. NOT rejected by TrustedAliasers/Barrier.
        assert_expected_events!(
            BulletinPolkadot,
            vec![ RuntimeEvent::MessageQueue(pallet_message_queue::Event::Processed { success: true, .. }) => {} ]
        );
        // Additional assertion: verify subsequent action taken "as" victim_bulletin_location succeeded,
        // proving impersonation, or that a Root-only call executed successfully.
    });
}
```
Expected (buggy) result: the message succeeds despite originating from an unprivileged signed AssetHub account. A fixed implementation should cause `Processed { success: false }` or an explicit `Barrier`/`Aliaser` rejection for this non-governance-marked origin.

### Citations

**File:** system-parachains/bulletin/bulletin-polkadot/src/xcm_config.rs (L113-135)
```rust
/// This is the type we use to convert an (incoming) XCM origin into a local `Origin` instance,
/// ready for dispatching a transaction with XCM's `Transact`. There is an `OriginKind` that can
/// bias the kind of local `Origin` it will become.
pub type XcmOriginToTransactDispatchOrigin = (
	// AssetHub or Relay can execute as root (based on: https://github.com/polkadot-fellows/runtimes/issues/651).
	// This will allow them to issue a transaction from the Root origin.
	LocationAsSuperuser<(Equals<RelayChainLocation>, Equals<AssetHubLocation>), RuntimeOrigin>,
	// Sovereign account converter; this attempts to derive an `AccountId` from the origin location
	// using `LocationToAccountId` and then turn that into the usual `Signed` origin. Useful for
	// foreign chains who want to have a local sovereign account on this chain that they control.
	SovereignSignedViaLocation<LocationToAccountId, RuntimeOrigin>,
	// Native converter for Relay-chain (Parent) location; will convert to a `Relay` origin when
	// recognized.
	RelayChainAsNative<RelayChainOrigin, RuntimeOrigin>,
	// Native converter for sibling Parachains; will convert to a `SiblingPara` origin when
	// recognized.
	SiblingParachainAsNative<cumulus_pallet_xcm::Origin, RuntimeOrigin>,
	// Native signed account converter; this just converts an `AccountId32` origin into a normal
	// `RuntimeOrigin::Signed` origin of the same 32-byte value.
	SignedAccountId32AsNative<RelayNetwork, RuntimeOrigin>,
	// XCM origins can be represented natively under the XCM pallet's `Xcm` origin.
	XcmPassthrough<RuntimeOrigin>,
);
```

**File:** system-parachains/bulletin/bulletin-polkadot/src/xcm_config.rs (L147-180)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyRecursively<DenyReserveTransferToRelayChain>,
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
					// Parent and its pluralities (i.e. governance bodies) get free execution.
					AllowExplicitUnpaidExecutionFrom<
						(
							ParentOrParentsPlurality,
							FellowsPlurality,
							Equals<GovernanceLocation>,
							AssetHubPlurality,
							// People chain has free execution for PoP authorizations.
							Equals<PeopleLocation>,
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

**File:** system-parachains/bulletin/bulletin-polkadot/src/xcm_config.rs (L197-208)
```rust
/// Defines origin aliasing rules for this chain.
///
/// - Allow any origin to alias into a child sub-location (equivalent to DescendOrigin),
/// - Allow same accounts to alias into each other across system chains,
/// - Allow AssetHub root to alias into anything,
/// - Allow origins explicitly authorized to alias into target location.
pub type TrustedAliasers = (
	AliasChildLocation,
	AliasAccountId32FromSiblingSystemChain,
	AliasOriginRootUsingFilter<AssetHubLocation, Everything>,
	AuthorizedAliasers<Runtime>,
);
```

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
