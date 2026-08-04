Only bridge-hub-polkadot and bulletin-polkadot use `DenyRecursively<DenyReserveTransferToRelayChain>`, confirming bridge-hub-kusama uses the non-recursive variant. This is consistent with my analysis.

### Title
`DenyReserveTransferToRelayChain` in Bridge Hub Kusama's `Barrier` only inspects top-level instructions, allowing bypass via nested `SetAppendix`/`SetErrorHandler` - (File: system-parachains/bridge-hubs/bridge-hub-kusama/src/xcm_config.rs)

### Finding Description
The `Barrier` type on Bridge Hub Kusama wraps `DenyReserveTransferToRelayChain` directly, without the `DenyRecursively` wrapper: `DenyThenTry<DenyReserveTransferToRelayChain, (...)>` [1](#0-0) . `DenyReserveTransferToRelayChain::should_execute` (defined in the external `xcm-builder` crate) matches the flat top-level `message.0` instruction slice for patterns like `InitiateReserveWithdraw{reserve: Parent, ..}` / `DepositReserveAsset{dest: Parent, ..}` / `TransferReserveAsset{dest: Parent, ..}`; it does not recurse into nested `Xcm` programs embedded inside `SetAppendix(Xcm(..))` or `SetErrorHandler(Xcm(..))`. Because the XCM executor's barrier check runs once, at the top level, before executing the message, an instruction sequence such as `[.., SetAppendix(Xcm(vec![InitiateReserveWithdraw{ reserve: Parent, .. }])), .. ]` never surfaces the denied instruction to the top-level pattern match, so the filter passes it through. Once past the barrier, the executor later runs the appendix (or error handler) in the same execution context without re-invoking the barrier, so the wrapped `InitiateReserveWithdraw` executes normally: it calls `AssetTransactor::withdraw_asset` on the user's local KSM holding and forwards a follow-up message to the Relay Chain. This is exactly the gap that the sibling `DenyRecursively` wrapper is designed to close, and it is already applied on Bridge Hub Polkadot's and Bulletin Polkadot's own `Barrier` (`DenyRecursively<DenyReserveTransferToRelayChain>`) but is missing on Bridge Hub Kusama [2](#0-1) [3](#0-2) . Note `IsReserve = ()` on Bridge Hub Kusama only governs trust for *incoming* `ReserveAssetDeposited` instructions [4](#0-3) ; it does not gate outbound `InitiateReserveWithdraw` execution, so the Barrier is the only real control preventing this class of message, and it is bypassable here.

### Impact Explanation
Once the wrapped `InitiateReserveWithdraw{reserve: Parent, ..}` executes, the executor debits the attacker's real local KSM balance via the asset transactor and dispatches a follow-on reserve-withdraw message to the Relay Chain. Since Bridge Hub KSM balances are backed by teleport (not sovereign-account reserve escrow, per the code comment "BridgeHub does not recognize a reserve location for any asset. Users must teleport KSM where allowed"), the Relay Chain side has no matching reserve balance to release; the outbound message either fails on the Relay Chain (asset gets trapped / lost) or, in the worst case, executes against a wrongly-assumed sovereign-account balance. Either way this breaks the intended invariant that Bridge Hub Kusama can never originate a reserve-transfer to the Relay Chain, and results in burned/frozen user funds rather than a successful, accounted-for transfer.

### Likelihood Explanation
The attacker only needs to be a signed local user (or sibling parachain) able to submit an XCM program via `pallet_xcm::execute` or an inbound XCMP message, staying within `MaxInstructions = 100`. Constructing `SetAppendix(Xcm(vec![InitiateReserveWithdraw{reserve: Parent, ..}]))` is a straightforward, deterministic, repeatable instruction sequence with no special privilege required, making this readily reachable by any unprivileged actor.

### Recommendation
Wrap `DenyReserveTransferToRelayChain` in `DenyRecursively` in Bridge Hub Kusama's `Barrier`, matching the pattern already used in Bridge Hub Polkadot and Bulletin Polkadot: change `DenyThenTry<DenyReserveTransferToRelayChain, (...)>` to `DenyThenTry<DenyRecursively<DenyReserveTransferToRelayChain>, (...)>` at [5](#0-4) .

### Proof of Concept
xcm-emulator / integration test plan:
1. Fund a test account on Bridge Hub Kusama with KSM.
2. Build an XCM program: `Xcm(vec![WithdrawAsset(ksm.clone()), BuyExecution{..}, SetAppendix(Xcm(vec![InitiateReserveWithdraw{ assets: All.into(), reserve: Parent.into(), xcm: Xcm(vec![]) }]))])`.
3. Submit via `pallet_xcm::execute` from a signed origin.
4. Assert (a) the `Barrier` does NOT reject the message (no `ProcessMessageError::Unsupported`/`Barrier` error emitted), (b) the appendix executes and the account's local KSM balance is debited, (c) either the follow-up message to the Relay Chain fails/traps the assets (`AssetTrap` event) or funds are unaccounted for on the Relay Chain side — confirming the local/reserve/bridged accounting invariant is broken.
5. Differential check: run the same program on Bridge Hub Polkadot (which uses `DenyRecursively`) and assert the Barrier correctly rejects it there, demonstrating the Kusama-specific gap.

### Citations

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

**File:** system-parachains/bridge-hubs/bridge-hub-kusama/src/xcm_config.rs (L200-202)
```rust
	// BridgeHub does not recognize a reserve location for any asset. Users must teleport KSM
	// where allowed (e.g. with the Relay Chain).
	type IsReserve = ();
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

**File:** system-parachains/bulletin/bulletin-polkadot/src/xcm_config.rs (L147-150)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyRecursively<DenyReserveTransferToRelayChain>,
		(
```
