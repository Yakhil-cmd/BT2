## Finding: Confirmed via codebase comparison

Inspecting `system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs`, the `Barrier` type deny-list uses the bare filter: [1](#0-0) 

Compare this with **the same runtime family's** `bridge-hub-polkadot` and `bulletin-polkadot`, which wrap the identical filter with `DenyRecursively`: [2](#0-1) [3](#0-2) 

`DenyRecursively` exists upstream (in `xcm-builder`, not vendored in this repo) specifically to recurse into nested `Xcm<()>` programs carried by instructions such as `SetAppendix`, `SetErrorHandler`, `DepositReserveAsset{ xcm, .. }`, `InitiateReserveWithdraw{ xcm, .. }`, `ExecuteWithOrigin`, etc. `DenyReserveTransferToRelayChain` on its own only pattern-matches the **top-level instruction slice** it is handed by `DenyThenTry`; it does not descend into these nested program fields. This is why bridge-hub-polkadot and bulletin-polkadot deliberately pair it with `DenyRecursively`, while asset-hub-polkadot, asset-hub-kusama, collectives-polkadot, coretime-polkadot/kusama, people-polkadot/kusama, and encointer do not.

### Why I can't fully validate the "duplicate DOT" claim

I could not find the `xcm-builder` crate's `DenyReserveTransferToRelayChain`/`DenyRecursively`/`XcmExecutor` implementation vendored in this repository, nor the relay chain's (`polkadot`) own `IsReserve`/`AssetTransactor` config, both of which are needed to trace the exact on-chain effect of a successfully-bypassed `InitiateReserveWithdraw{ reserve: Parent, .. }` reaching the relay. Based on the semantics of that instruction (burn locally, then `WithdrawAsset` from the sender's sovereign account on the "reserve" location), the most defensible outcome is that DOT held in AssetHubPolkadot's sovereign account on the relay chain would be drained/burned against a local burn on Asset Hub — this is a fund-loss/burn scenario, not necessarily a "duplicate DOT" mint, and its exact success depends on the relay-side sovereign account balance and asset-transactor behavior that I cannot verify from this codebase alone.

### Title
Missing `DenyRecursively` wrapper on `DenyReserveTransferToRelayChain` allows nested-instruction bypass of the DOT reserve-transfer-to-relay ban - (File: `system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs`)

### Summary
`asset-hub-polkadot`'s `Barrier` uses a bare `DenyReserveTransferToRelayChain`, which only shallow-matches top-level instructions, whereas sibling system chains (`bridge-hub-polkadot`, `bulletin-polkadot`) explicitly wrap the same filter in `DenyRecursively` to catch the ban-listed instructions nested inside `SetAppendix`/`SetErrorHandler`/other nested-`Xcm<()>`-carrying instructions. This inconsistency means a locally-executed program (e.g., via `pallet_xcm::execute`) that places `InitiateReserveWithdraw{reserve: Parent, ..}` inside a `SetAppendix`/`SetErrorHandler` continuation would not be caught by the deny check at entry, since only the outer instruction list is scanned and the appendix/error-handler body executes later without a second `ShouldExecute` pass.

### Finding Description
`DenyThenTry<DenyReserveTransferToRelayChain, ...>` is evaluated once against the top-level instruction slice of an incoming/self-executed program. `DenyReserveTransferToRelayChain` pattern-matches specific top-level instructions (`InitiateReserveWithdraw`, `DepositReserveAsset`, `TransferReserveAsset` targeting `(1, Here)`); it does not recurse into `Xcm<()>` payloads embedded in `SetAppendix`/`SetErrorHandler`. Those nested programs are executed later by the `XcmExecutor` without a fresh `Barrier::should_execute` invocation. Consequently, wrapping the denied instruction inside such a nested program lets it slip past the deny stage while still executing. This is the exact gap `DenyRecursively` closes elsewhere in the same codebase.

### Impact Explanation
If exploitable, an unprivileged signed user on AssetHubPolkadot could get a normally-forbidden DOT reserve-withdraw-to-relay executed, bypassing the explicit protection intended to prevent inconsistent DOT accounting between the teleport-based AssetHub/relay DOT relationship and reserve-transfer semantics. The precise ledger consequence (burn without compensating release, drain of AssetHubPolkadot's relay-side sovereign account, or duplicate DOT) depends on relay-side `AssetTransactor`/`IsReserve` behavior not present in this repo, so the impact is real but its exact financial shape could not be fully confirmed here.

### Likelihood Explanation
Reachable via `pallet_xcm::execute()` from any signed account with a program containing a `BuyExecution`/paid-execution instruction to satisfy `AllowTopLevelPaidExecutionFrom<Everything>`, plus a `SetAppendix`/`SetErrorHandler` carrying the banned instruction. No privileged origin, proxy bypass, or governance action is required — only ordinary XCM program construction.

### Recommendation
Wrap `DenyReserveTransferToRelayChain` in `DenyRecursively` in `asset-hub-polkadot`'s (and the other affected chains') `Barrier` definition, matching the pattern already used in `bridge-hub-polkadot`/`bulletin-polkadot`, so nested `SetAppendix`/`SetErrorHandler`/other nested-`Xcm<()>` payloads are scanned recursively before any XCM program is admitted.

### Proof of Concept
xcm-emulator test in `integration-tests/emulated/tests/assets/asset-hub-polkadot`:
1. Fund a signed AssetHubPolkadot account with DOT.
2. Call `PolkadotXcm::execute` with a program: `[WithdrawAsset(DOT), BuyExecution(DOT), SetAppendix(Xcm([InitiateReserveWithdraw{ assets: All, reserve: Parent, xcm: [DepositAsset(beneficiary)] }]))]`.
3. Assert the call does **not** revert with the deny-barrier error (demonstrating the bypass at the `should_execute` stage), then assert on the relay chain (`Polkadot::execute_with`) whether DOT was created/moved unexpectedly — comparing total DOT issuance/sovereign-account balances before and after to confirm whether the cross-chain balanced-accounting invariant is broken.

### Citations

**File:** system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs (L374-376)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyReserveTransferToRelayChain,
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
