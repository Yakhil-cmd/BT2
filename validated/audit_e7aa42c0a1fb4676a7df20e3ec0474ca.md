### Title
Unprivileged AssetHub signed account can alias into any People-chain account via `AliasOriginRootUsingFilter<AssetHubLocation, Everything>` - (File: system-parachains/people/people-kusama/src/xcm_config.rs)

### Summary
The `TrustedAliasers` tuple on the People chain includes `AliasOriginRootUsingFilter<AssetHubLocation, Everything>` inside a `WithComputedOrigin` barrier that also grants `AllowExplicitUnpaidExecutionFrom` free execution to messages whose origin equals `AssetHubLocation`. Because XCMP-transported messages are attributed to the *whole sending parachain* (not to the specific account that triggered `pallet_xcm::send` on that chain), any signed AssetHub account — not just AssetHub governance/root — can produce a message that arrives at the People chain with origin exactly `AssetHubLocation`, satisfying the aliaser's exact-match check, and the `Everything` filter then lets that origin alias into any arbitrary People-chain location.

### Finding Description
The relevant configuration is: [1](#0-0) 

`WithComputedOrigin` wraps `AllowExplicitUnpaidExecutionFrom<(..., Equals<AssetHubLocation>, ...), TrustedAliasers>`, and `TrustedAliasers` includes `AliasOriginRootUsingFilter<AssetHubLocation, Everything>`. The design intent, per the surrounding doc comment ("Allow AssetHub root to alias into anything"), is that only AssetHub's *root/governance* should hold this power — mirroring the `LocationAsSuperuser<(Equals<RelayChainLocation>, Equals<AssetHubLocation>)>` entry in `XcmOriginToTransactDispatchOrigin`: [2](#0-1) 

However, the *origin* that the People chain's `XcmExecutor` sees for a message delivered via the AssetHub↔People HRMP/XCMP channel is determined solely by the transport layer as the sending parachain's bare location (`(1, [Parachain(AssetHub_id)])` == `AssetHubLocation`), regardless of which internal account on AssetHub triggered the send. There is nothing in `pallet_xcm::Config` on AssetHub (`SendXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalOriginToLocation>`) that restricts the `send` extrinsic to privileged callers — any signed AssetHub account can call `pallet_xcm::send(dest = People, message = Xcm([AliasOrigin(target), Transact(...)]))`. Distinguishing a specific AssetHub sub-account from the chain root would require the sender to explicitly prepend origin-narrowing instructions, which the aliaser mechanism (`AliasChildLocation`, `AliasAccountId32FromSiblingSystemChain`) exists precisely to gate — but `AliasOriginRootUsingFilter<AssetHubLocation, Everything>` bypasses that narrowing entirely for the exact `AssetHubLocation` origin, and since the filter is `Everything`, it does not restrict the alias *target* at all.

The exploit path is therefore:
1. Attacker (any signed AssetHub account) calls `pallet_xcm::send` with a message `[AliasOrigin{ target: victim_location }, Transact{ call: <arbitrary_call>, origin_kind: ... }]`, destined for the People chain.
2. Message is routed via XCMP; on arrival, `XcmExecutor::execute_xcm` is invoked with `origin = AssetHubLocation`.
3. `Barrier`'s `WithComputedOrigin` → `AllowExplicitUnpaidExecutionFrom<..., Equals<AssetHubLocation>, ..., TrustedAliasers>` matches on `Equals<AssetHubLocation>`, granting free execution.
4. `AliasOrigin` instruction is checked via `Aliasers = TrustedAliasers`; `AliasOriginRootUsingFilter<AssetHubLocation, Everything>` matches because `origin == AssetHubLocation` exactly, and the `Everything` filter accepts any `target`.
5. The origin register becomes `victim_location`; the subsequent `Transact` is dispatched through `XcmOriginToTransactDispatchOrigin`, converting `victim_location` into `RuntimeOrigin::Signed(victim_account)` (or similar), letting the attacker execute arbitrary calls as the victim without paying fees.

None of the existing checks (Barrier, `SafeCallFilter = Everything`, `OriginConverter`) stop this, because the entire chain-level trust extended to `AssetHubLocation` is not scoped to AssetHub's governance/root — it is granted to whichever entity can cause any XCM to be routed from AssetHub, which is any signed AssetHub user via `pallet_xcm::send`.

### Impact Explanation
An unprivileged AssetHub account can impersonate any account (or the local root/pallet locations) on the People chain, bypassing fee payment (`AllowExplicitUnpaidExecutionFrom`) and executing arbitrary `Transact` calls as that victim — e.g., changing identity data, judgement requests, sub-identities, or any dispatchable reachable from a `Signed` origin on People chain, and potentially reaching privileged pallet-internal accounts if their locations can be described. This is origin impersonation of arbitrary people-chain accounts, matching the scoped impact.

### Likelihood Explanation
Feasibility depends only on: (1) any signed AssetHub account being able to call `pallet_xcm::send` with an arbitrary destination/message (standard, unprivileged capability in these runtimes), and (2) XCMP transport attributing the message's origin to the whole sending parachain rather than the internal account — both of which are established, unconditional features of the Polkadot SDK XCM/XCMP transport and this runtime's `pallet_xcm` configuration. No governance, sudo, or relayer collusion is required; the attack is fully repeatable and requires only paying the ordinary XCMP delivery fee.

### Recommendation
Restrict `AliasOriginRootUsingFilter<AssetHubLocation, Everything>`'s filter to a narrowly scoped set of trusted destination locations (e.g., only AssetHub's own root/plurality-controlled People-chain accounts, or remove this aliaser entirely in favor of `AuthorizedAliasers<Runtime>` opt-in), so that the "AssetHub root" trust is not implicitly extended to every unprivileged AssetHub account capable of triggering `pallet_xcm::send`. Alternatively, gate the alias/free-execution barrier to only accept messages carrying an explicit governance-body proof rather than the bare parachain-level `Equals<AssetHubLocation>` origin.

### Proof of Concept
xcm-emulator integration test (People-Kusama + AssetHub-Kusama):
```rust
#[test]
fn unprivileged_assethub_account_cannot_alias_into_arbitrary_people_account() {
    // Setup: AssetHub signed account `ALICE` (not root, not OpenGov track), People-chain victim `BOB`.
    AssetHubKusama::execute_with(|| {
        let alice = AssetHubKusamaSender::get(); // ordinary signed account
        let message: Xcm<()> = Xcm(vec![
            AliasOrigin(bob_location_on_people_chain()),
            Transact {
                origin_kind: OriginKind::SovereignAccount,
                call: people_kusama_runtime::RuntimeCall::System(
                    frame_system::Call::remark { remark: b"pwned".to_vec() }
                ).encode().into(),
                fallback_max_weight: None,
            },
        ]);
        // Send as an ordinary signed extrinsic call to pallet_xcm::send
        assert_ok!(PolkadotXcm::send(
            RuntimeOrigin::signed(alice),
            Box::new(PeopleKusama::sibling_location_of(PeopleKusama::para_id()).into()),
            Box::new(VersionedXcm::from(message)),
        ));
    });

    PeopleKusama::execute_with(|| {
        // Expected (secure) result: message rejected by Barrier/Aliaser, `bob`'s account state unchanged.
        assert!(!System::events().iter().any(|e| matches!(
            e.event,
            RuntimeEvent::System(frame_system::Event::Remarked { sender, .. }) if sender == bob_account()
        )));
    });
}
```
Expected (current, vulnerable) behavior: the `Transact` executes with `Signed(bob_account())` origin without any fee payment, proving unauthorized origin impersonation. A fix should make this assertion pass (no unauthorized execution as `bob`).

### Citations

**File:** system-parachains/people/people-kusama/src/xcm_config.rs (L142-144)
```rust
	// AssetHub or Relay can execute as root (based on: https://github.com/polkadot-fellows/runtimes/issues/651).
	// This will allow them to issue a transaction from the Root origin.
	LocationAsSuperuser<(Equals<RelayChainLocation>, Equals<AssetHubLocation>), RuntimeOrigin>,
```

**File:** system-parachains/people/people-kusama/src/xcm_config.rs (L166-219)
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
					// Parent and its pluralities (i.e. governance bodies) get free execution.
					AllowExplicitUnpaidExecutionFrom<
						(
							ParentOrParentsPlurality,
							// For OpenGov on AH
							Equals<AssetHubLocation>,
							AssetHubPlurality,
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

/// Locations that will not be charged fees in the executor, neither for execution nor delivery. We
/// only waive fees for system functions, which these locations represent.
pub type WaivedLocations = (
	Equals<RootLocation>,
	RelayOrOtherSystemParachains<AllSiblingSystemParachains, Runtime>,
	Equals<RelayTreasuryLocation>,
	LocalPlurality,
);

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
