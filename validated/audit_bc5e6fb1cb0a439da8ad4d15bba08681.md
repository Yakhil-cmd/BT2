### Title
`DenyReserveTransferToRelayChain` barrier bypass via nested XCM instructions on bridge-hub-kusama - ([File: system-parachains/bridge-hubs/bridge-hub-kusama/src/xcm_config.rs])

### Summary
`bridge-hub-kusama`'s `Barrier` wraps `DenyReserveTransferToRelayChain` directly in `DenyThenTry` without the `DenyRecursively` wrapper, unlike `bridge-hub-polkadot` and `bulletin-polkadot`, which explicitly use `DenyRecursively<DenyReserveTransferToRelayChain>`. Because the plain (non-recursive) deny filter only scans the top-level instruction sequence of an incoming `Xcm` program, an attacker can smuggle a reserve-transfer-to-Relay-Chain instruction inside a nested `Xcm` payload of an otherwise-allowed outer instruction, bypassing the intended deny.

### Finding Description
The barrier is defined as: [1](#0-0) 

Compare this to `bridge-hub-polkadot`, which was hardened to wrap the same deny filter with `DenyRecursively`: [2](#0-1) 

and `bulletin-polkadot`, which similarly uses `DenyRecursively<DenyReserveTransferToRelayChain>`: [3](#0-2) 

`DenyRecursively` was introduced in `xcm-builder` specifically because the plain `Deny*` filters (including `DenyReserveTransferToRelayChain`) are invoked once, over the top-level instruction list of the program handed to the executor's `Barrier::should_execute`. They do not descend into `Xcm<Call>` payloads nested inside instructions such as `SetAppendix`, `ExecuteWithOrigin`, `InitiateReserveWithdraw { xcm, .. }`, or `DepositReserveAsset { xcm, .. }`. An attacker can therefore craft an outer program whose top-level instructions satisfy `AllowTopLevelPaidExecutionFrom<Everything>` (e.g. `WithdrawAsset`, `BuyExecution`, then `SetAppendix(inner)` or an instruction carrying a nested continuation), while placing the actual `InitiateReserveWithdraw { reserve: RelayChainLocation, .. }` inside that nested `inner` program. The top-level non-recursive `DenyReserveTransferToRelayChain` scan never inspects `inner`, so `DenyThenTry` falls through to the allow-side filters (`AllowTopLevelPaidExecutionFrom<Everything>`), which are satisfied by the outer program, and the whole message — including the nested reserve-withdraw — is admitted and executed by `XcmExecutor`.

This is reachable by any signed account via `pallet_xcm::execute` (or `send`), since `AllowTopLevelPaidExecutionFrom<Everything>` in the `WithComputedOrigin` stack imposes no origin restriction beyond paying for execution.

### Impact Explanation
The scoped impact is that the explicit deny on reserve-transfers to the Relay Chain — an invariant this bridge-hub relies on because it sets `type IsReserve = ();` and expects users to teleport KSM instead — can be circumvented via nested XCM, allowing an unprivileged user's message to reach and execute the `InitiateReserveWithdraw`/reserve-transfer code path that governance explicitly intended to block. This defeats the barrier/filter invariant ("filters ... must not be bypassable by normal users") even though downstream asset-backing checks on the Relay Chain (verifying BridgeHub's sovereign account balance) would still constrain any actual fund movement — the vulnerability is the filter bypass itself, not necessarily unbacked asset creation.

### Likelihood Explanation
Preconditions are minimal: any signed account able to call `pallet_xcm::execute` or `send` can submit a crafted `Xcm` program. No privileged origin, proxy proof, or special asset holdings beyond enough balance to pay execution fees are required. The bypass is deterministic and repeatable — it is a structural gap in `DenyThenTry<DenyReserveTransferToRelayChain, ...>` versus the hardened `DenyThenTry<DenyRecursively<DenyReserveTransferToRelayChain>, ...>` pattern already adopted elsewhere in this same repository.

### Recommendation
Wrap `DenyReserveTransferToRelayChain` (and ideally any other `Deny*` filters used in this barrier) with `DenyRecursively` in `bridge-hub-kusama/src/xcm_config.rs`, mirroring `bridge-hub-polkadot`:
```rust
pub type Barrier = TrailingSetTopicAsId<
    DenyThenTry<
        DenyRecursively<DenyReserveTransferToRelayChain>,
        ( ... )
    >,
>;
```
Audit other Kusama/Polkadot system-chain runtimes in this repo using the plain (non-recursive) `DenyReserveTransferToRelayChain` for the same gap.

### Proof of Concept
xcm-emulator test plan (BridgeHubKusama):
1. Build an outer `Xcm` executed via `pallet_xcm::execute` from a funded signed account: `WithdrawAsset`, `BuyExecution`, `SetAppendix(inner_xcm)` where `inner_xcm = Xcm(vec![InitiateReserveWithdraw { assets: Wild(All), reserve: RelayChainLocation::get(), xcm: Xcm(vec![]) }])`.
2. Assert that under the current (non-recursive) barrier the outer call succeeds (`Outcome::Complete`/no `Barrier` error) and an XCM is forwarded toward the Relay Chain — proving the deny was bypassed.
3. Repeat the same program against a copy of the config with `DenyRecursively<DenyReserveTransferToRelayChain>` substituted, and assert the message is now rejected with a `Barrier` error, demonstrating the fix closes the gap.

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

**File:** system-parachains/bulletin/bulletin-polkadot/src/xcm_config.rs (L147-149)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyRecursively<DenyReserveTransferToRelayChain>,
```
