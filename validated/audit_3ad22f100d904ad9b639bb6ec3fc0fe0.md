### Title
`DenyReserveTransferToRelayChain` only inspects top-level XCM instructions and is not wrapped in `DenyRecursively` on Coretime chains, allowing the deny-filter to be bypassed via `SetAppendix`/`SetErrorHandler` nesting - ([File: system-parachains/coretime/coretime-kusama/src/xcm_config.rs], [File: system-parachains/coretime/coretime-polkadot/src/xcm_config.rs])

### Summary
Coretime's `Barrier` wraps the deny check as `DenyThenTry<DenyReserveTransferToRelayChain, ...>` [1](#0-0) , while the sibling `bulletin-polkadot` and `bridge-hub-polkadot` chains use `DenyThenTry<DenyRecursively<DenyReserveTransferToRelayChain>, ...>` [2](#0-1) [3](#0-2) . The existence of the `DenyRecursively` wrapper in this same repo confirms that plain `DenyReserveTransferToRelayChain` only scans the flat top-level instruction list of an incoming XCM and does not recurse into the nested instruction sequences carried inside `SetAppendix`/`SetErrorHandler`, meaning it can be bypassed on chains that omit the wrapper.

### Finding Description
The `Barrier` type on `coretime-kusama` and `coretime-polkadot` is defined as `TrailingSetTopicAsId<DenyThenTry<DenyReserveTransferToRelayChain, (...)>>` [4](#0-3) [5](#0-4) . This is identical in shape to the barriers of asset-hub-kusama/polkadot, collectives-polkadot, people-kusama/polkadot, bridge-hub-kusama, and encointer, all of which also lack the `DenyRecursively` wrapper.

By contrast, `bulletin-polkadot` uses `DenyRecursively<DenyReserveTransferToRelayChain>` [2](#0-1) , and `bridge-hub-polkadot` uses `(DenyRecursively<DenyReserveTransferToRelayChain>, DenyRecursively<DenyExportMessageFrom<...>>)` [3](#0-2) . The presence of this recursive wrapper in the codebase demonstrates that the plain (non-recursive) `DenyReserveTransferToRelayChain` filter, as used by Coretime, checks only the flat/top-level instruction sequence of the incoming `Xcm` program and does not walk into the nested `Xcm<RuntimeCall>` sequences embedded inside `SetAppendix(xcm)` or `SetErrorHandler(xcm)` instructions. Because `SetAppendix`/`SetErrorHandler` blocks are executed by the same XCM executor/holding register after (or on failure of) the main program - they are not inert metadata - an attacker can place `InitiateReserveWithdraw { reserve: Parent, xcm: [...] }` or `DepositReserveAsset { dest: Parent, ... }` inside a `SetAppendix`/`SetErrorHandler` block so the deny check's shallow scan of the outer instruction list never matches the pattern, yet the executor still runs those instructions as part of the same call.

An unprivileged signed user reaching `pallet_xcm::execute` on Coretime (local XCM execution) can therefore submit a top-level program that passes `DenyReserveTransferToRelayChain::deny` trivially (e.g., a benign `WithdrawAsset`/`BuyExecution` sequence), with a `SetAppendix` containing the actual `InitiateReserveWithdraw(reserve=Parent, ...)`/`DepositReserveAsset(dest=Parent, ...)` instruction. The `WithComputedOrigin` and other `Allow*` items in the try-list only run after the deny stage and do not re-check for the denied pattern either, so nothing downstream catches the bypass.

### Impact Explanation
This lets a Coretime user drive an XCM program that structurally routes assets to the Relay Chain via the reserve-transfer mechanism, which Coretime's XCM config explicitly disallows (`IsReserve = ()`, comment: "Coretime chain does not recognize a reserve location for any asset. Users must teleport DOT where allowed") [6](#0-5) . This breaks the intended invariant that system parachains only move the native token to/from the Relay Chain via teleport, not reserve-transfer, and can trigger unexpected reserve-based message processing/accounting on the Relay Chain from Coretime's sovereign account - the exact "non-reserve invariant" scenario `DenyReserveTransferToRelayChain` exists to prevent. The practical value extractable is bounded by whatever balance sits in Coretime's sovereign account on the Relay Chain, but the filter-bypass itself is a genuine barrier defect, not merely a theoretical gap, since the fix (`DenyRecursively`) already exists and is applied elsewhere in the same codebase.

### Likelihood Explanation
Preconditions are minimal: any signed account able to call `pallet_xcm::execute` on `coretime-kusama`/`coretime-polkadot` can attempt this, no privileged origin or proxy is required. The bypass is deterministic and repeatable - it only depends on constructing a valid encoded `Xcm` program with the denied instruction nested inside `SetAppendix`/`SetErrorHandler` rather than at the top level, which is fully within normal user capability via the `pallet_xcm::execute` extrinsic.

### Recommendation
Wrap the deny filter with the recursive variant already used elsewhere in this repository, e.g. change:
```rust
DenyThenTry<DenyReserveTransferToRelayChain, (...)>
```
to
```rust
DenyThenTry<DenyRecursively<DenyReserveTransferToRelayChain>, (...)>
```
in `system-parachains/coretime/coretime-kusama/src/xcm_config.rs` and `system-parachains/coretime/coretime-polkadot/src/xcm_config.rs`, matching the pattern already applied in `bulletin-polkadot/src/xcm_config.rs` and `bridge-hub-polkadot/src/xcm_config.rs`. The same audit should be extended to `asset-hub-kusama`, `asset-hub-polkadot`, `collectives-polkadot`, `bridge-hub-kusama`, `people-kusama`, `people-polkadot`, and `encointer`, which show the identical non-recursive pattern.

### Proof of Concept
xcm-emulator / integration test plan for `coretime-polkadot`:
1. Fund a test signed account with native DOT sufficient to pay fees on Coretime.
2. Construct `Xcm([WithdrawAsset(fees), BuyExecution(fees), SetAppendix(Xcm([InitiateReserveWithdraw { assets: All, reserve: Location::parent(), xcm: Xcm([BuyExecution(...), DepositAsset { assets: All, beneficiary: attacker_on_relay }]) }])), DepositAsset { assets: All, beneficiary: attacker_on_coretime }])`.
3. Call `pallet_xcm::execute(origin=signed(attacker), message, weight_limit)`.
4. Assert `DenyReserveTransferToRelayChain::deny` on the top-level message returns `Ok(())` (i.e., does not block), confirming the shallow scan is bypassed.
5. Assert that the appendix executes and a reserve-related XCM (`WithdrawAsset`+`DepositAsset`) is actually sent to/processed against the Relay Chain sovereign account, evidenced by an `AssetsTrapped`/XCMP message queued to the Relay in the emulator's message bus, proving the deny-filter's intended invariant was violated despite the filter being configured.
6. As a regression fix verification, re-run the same test after wrapping the filter in `DenyRecursively` and assert `pallet_xcm::execute` now fails with `ProcessMessageError`/barrier rejection.

### Citations

**File:** system-parachains/coretime/coretime-polkadot/src/xcm_config.rs (L159-191)
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
					// If the message is one that immediately attemps to pay for execution, then
					// allow it.
					AllowTopLevelPaidExecutionFrom<Everything>,
					// Parent and its pluralities (i.e. governance bodies) get free execution.
					AllowExplicitUnpaidExecutionFrom<
						(
							ParentOrParentsPlurality,
							FellowsPlurality,
							Equals<RelayTreasuryLocation>,
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

**File:** system-parachains/coretime/coretime-polkadot/src/xcm_config.rs (L234-238)
```rust
	// Coretime chain does not recognize a reserve location for any asset. Users must teleport DOT
	// where allowed (e.g. with the Relay Chain).
	type IsReserve = ();
	/// Only allow teleportation of DOT.
	type IsTeleporter = ConcreteAssetFromSystem<DotRelayLocation>;
```

**File:** system-parachains/bulletin/bulletin-polkadot/src/xcm_config.rs (L147-150)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyRecursively<DenyReserveTransferToRelayChain>,
		(
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

**File:** system-parachains/coretime/coretime-kusama/src/xcm_config.rs (L153-184)
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
					// If the message is one that immediately attemps to pay for execution, then
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
