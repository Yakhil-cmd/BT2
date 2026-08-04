## Analysis

`People-kusama`'s `Barrier` uses the bare `DenyReserveTransferToRelayChain` filter, without the `DenyRecursively` wrapper that other chains in this same codebase apply to the identical filter: [1](#0-0) 

Compare this with `bridge-hub-polkadot` and `bulletin-polkadot`, which wrap the same filter in `DenyRecursively<...>`: [2](#0-1) [3](#0-2) 

The `xcm-builder::DenyRecursively` combinator exists specifically to apply an inner `ShouldExecute` filter (like `DenyReserveTransferToRelayChain`) recursively into nested XCM programs embedded in instructions such as `SetAppendix` and `SetErrorHandler`, because `DenyReserveTransferToRelayChain`'s own check only scans the top-level instruction slice passed to `should_execute`, not instructions nested inside those sub-programs. `People-kusama` (along with `asset-hub-kusama`, `asset-hub-polkadot`, `coretime-kusama`, `coretime-polkadot`, `collectives-polkadot`, `people-polkadot`) lacks this wrapper.

`People-kusama` does hold/transact KSM natively (`FungibleTransactor` with `IsConcrete<RelayChainLocation>`), so a reserve-transfer of KSM to the Relay Chain executed from this chain has real asset-accounting impact: [4](#0-3) 

### Title
Missing `DenyRecursively` wrapping allows `DenyReserveTransferToRelayChain` bypass via nested `SetAppendix`/`SetErrorHandler` instructions - (File: system-parachains/people/people-kusama/src/xcm_config.rs)

### Summary
The `Barrier` for People-kusama denies reserve-transfer-to-relay-chain instructions only at the top level of an incoming XCM program via `DenyReserveTransferToRelayChain`, but does not wrap it in `DenyRecursively` as done for `bridge-hub-polkadot` and `bulletin-polkadot` in the same codebase. An attacker can place the denied `DepositReserveAsset`/`TransferReserveAsset`/`InitiateReserveWithdraw` instruction targeting the Relay Chain inside a nested `SetAppendix` or `SetErrorHandler` sub-program, which is not inspected by the top-level scan, letting the deny-filter be bypassed while the nested reserve-transfer still executes when the appendix/error handler runs.

### Finding Description
`DenyReserveTransferToRelayChain::should_execute` inspects only the top-level instruction slice of the incoming `Xcm` program for `InitiateReserveWithdraw`/`DepositReserveAsset`/`TransferReserveAsset` targeting `(1, Here)`. Instructions like `SetAppendix(Xcm<Call>)` and `SetErrorHandler(Xcm<Call>)` carry an entire nested `Xcm` program as their payload; that nested program is a separate `Vec<Instruction>` that is not flattened into, or otherwise visited by, the top-level `.iter()` scan the deny filter performs. The `xcm-executor` runs the appendix (on normal completion) or the error handler (on error) using the same origin/holding-register context as the main program, but it does this internal sub-execution without re-invoking the top-level `Barrier` on that nested program. This is precisely the gap `DenyRecursively` closes — by wrapping an inner `ShouldExecute` filter, it recurses into `SetAppendix`/`SetErrorHandler` payloads to apply the same deny logic there. `People-kusama`'s `Barrier` uses the bare, non-recursive `DenyReserveTransferToRelayChain`, so an attacker-controlled sibling/sovereign account with assets already present in People-kusama's holding register can send an XCM whose top-level program is benign (or contains an allowed no-op) but whose `SetAppendix`/`SetErrorHandler` payload contains `DepositReserveAsset { dest: (Parent, Here), .. }`. The top-level deny check passes because it never inspects the nested payload, and the reserve-transfer to the Relay Chain subsequently executes when the appendix/error handler runs.

### Impact Explanation
This allows an unprivileged, XCM-capable attacker (any sovereign/local account that can send arbitrary XCM to People-kusama and has assets available in the holding register, e.g. KSM held via `FungibleTransactor`) to perform a reserve transfer of KSM from People-kusama to the Relay Chain despite the chain's explicit intent to deny this path — bypassing the intended barrier restriction and moving assets to/through the relay chain outside the sanctioned route.

### Likelihood Explanation
Feasible and repeatable: it requires no privileged origin, only the ability to send/execute an XCM program on People-kusama with attacker-controlled assets in holding (e.g., via a prior teleport/deposit into the executing context, or as a sibling sovereign account). Constructing a `SetAppendix`/`SetErrorHandler`-wrapped reserve transfer is straightforward XCM composition and does not require exploiting any race condition.

### Recommendation
Wrap `DenyReserveTransferToRelayChain` in `DenyRecursively` for `People-kusama`'s `Barrier` (and audit/fix the other affected chains — `asset-hub-kusama`, `asset-hub-polkadot`, `coretime-kusama`, `coretime-polkadot`, `collectives-polkadot`, `people-polkadot` — which have the same bare, non-recursive usage), matching the pattern already used in `bridge-hub-polkadot`/`bulletin-polkadot`:
```rust
pub type Barrier = TrailingSetTopicAsId<
    DenyThenTry<
        DenyRecursively<DenyReserveTransferToRelayChain>,
        ( ... )
    >,
>;
```

### Proof of Concept
xcm-emulator integration test on `people-kusama`:
1. Fund an attacker-controlled sibling parachain sovereign account on `people-kusama` with KSM.
2. Craft an XCM program executed with that origin: top-level instructions are just `WithdrawAsset`/`ClearOrigin` (innocuous, passes `DenyReserveTransferToRelayChain`), but with `SetAppendix(Xcm(vec![DepositReserveAsset { assets: ..., dest: (Parent, Here).into(), xcm: Xcm(vec![]) }]))` set before program completion.
3. Assert: after execution, KSM balance/accounting reflects a successful reserve-transfer effect to the Relay Chain (e.g., relay-side reserve asset deposit registered, or People-kusama sovereign/holding balance decreased accordingly), proving the deny-filter was bypassed.
4. Compare against a canonical top-level `DepositReserveAsset{dest: Parent}` message and assert it is denied (`ProcessMessageError::Unsupported`), while the nested/appendix variant is not — demonstrating the inconsistency.

### Citations

**File:** system-parachains/people/people-kusama/src/xcm_config.rs (L113-125)
```rust
/// Means for transacting the native currency on this chain.
pub type FungibleTransactor = FungibleAdapter<
	// Use this currency:
	Balances,
	// Use this currency when it is a fungible asset matching the given location or name:
	IsConcrete<RelayChainLocation>,
	// Convert an XCM `Location` into a local account ID:
	LocationToAccountId,
	// Our chain's account ID type (we can't get away without mentioning it explicitly):
	AccountId,
	// We don't track any teleports of `Balances`.
	(),
>;
```

**File:** system-parachains/people/people-kusama/src/xcm_config.rs (L166-197)
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
