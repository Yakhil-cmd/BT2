### Title
`DenyReserveTransferToRelayChain` in Asset Hub Polkadot's `Barrier` only inspects top-level instructions, allowing reserve-transfer-to-Relay via nested `SetAppendix`/`SetErrorHandler` - ([File: system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs])

### Summary
Asset Hub Polkadot's `Barrier` wraps `DenyReserveTransferToRelayChain` directly (not through the recursive wrapper used elsewhere in this same repo), so the deny-list check is evaluated only against the outer instruction vector passed to the XCM executor. Nested XCM programs embedded via `SetAppendix`/`SetErrorHandler` (executed later by the same executor instance without a second `Barrier::should_execute` call) are not re-checked, so a `DepositReserveAsset`/`InitiateReserveWithdraw{ dest: Parent, .. }` hidden inside an appendix/error handler bypasses the deny filter.

### Finding Description
The `Barrier` type for Asset Hub Polkadot is: [1](#0-0) 
This uses the bare `DenyReserveTransferToRelayChain`, unlike Bridge Hub Polkadot and Bulletin Polkadot in the same repository, which explicitly wrap it as `DenyRecursively<DenyReserveTransferToRelayChain>`: [2](#0-1) [3](#0-2) 

This asymmetry within the same codebase indicates that `DenyReserveTransferToRelayChain::deny` (defined in the external `xcm-builder` crate, not present in this repo's index) inspects only the top-level `Vec<Instruction>` of the message handed to the XCM executor at `prepare`/barrier-check time. `DenyRecursively` was introduced specifically to walk into nested XCM programs (e.g. those embedded in `SetAppendix`, `SetErrorHandler`, and similar constructs) and was deliberately applied to Bridge Hub and Bulletin, but this fix has not been applied to Asset Hub Polkadot (nor Asset Hub Kusama, Collectives, Coretime, or People chains, which also use the bare filter).

Because the XCM executor evaluates the configured `Barrier` once against the top-level instruction sequence, and only stores/executes the appendix or error handler afterward as part of normal instruction processing (without a second barrier evaluation), a signed user calling `pallet_xcm::execute` can submit a program whose top-level instructions are benign/pass the barrier (e.g. `WithdrawAsset` + `SetAppendix`), while the appendix contains `DepositReserveAsset { dest: Parent, .. }` or `InitiateReserveWithdraw { reserve: Parent, .. }`. This nested instruction executes without ever being evaluated by `DenyReserveTransferToRelayChain`, defeating the "reserve-transfer-to-relay is always denied" invariant.

### Impact Explanation
An unprivileged, signed holder of DOT (or other reserve-backed assets) on Asset Hub Polkadot can move assets to the Relay Chain via the reserve-transfer path that the runtime authors explicitly intended to block, bypassing the intended routing/accounting model for DOT reserve transfers between Asset Hub and the Relay Chain. This can cause reserve accounting mismatches between the two chains' `pallet_balances`/asset trackers, since the "safe" teleport-only policy for native DOT movement between Relay and Asset Hub is circumvented.

### Likelihood Explanation
Requires only a signed account with a DOT balance and access to `pallet_xcm::execute`, which is a normal user-facing extrinsic with no special permission requirements beyond the caller having assets to move. The attack is fully repeatable and does not depend on validator/collator behavior, races, or governance actions — it depends purely on whether `DenyReserveTransferToRelayChain`'s `deny` implementation recurses into nested instructions, which I cannot directly confirm from this repo since the type is defined in the external `xcm-builder` crate and not indexed here. The strong circumstantial evidence is the repo's own use of `DenyRecursively` on Bridge Hub/Bulletin but not on Asset Hub, which is the documented reason `DenyRecursively` exists upstream (to close exactly this nested-instruction bypass).

### Recommendation
Wrap `DenyReserveTransferToRelayChain` with `DenyRecursively` in Asset Hub Polkadot's (and Asset Hub Kusama's, Collectives', Coretime's, People's) `Barrier` definition, matching the pattern already used in `bridge-hub-polkadot` and `bulletin-polkadot`:
```rust
pub type Barrier = TrailingSetTopicAsId<
    DenyThenTry<
        DenyRecursively<DenyReserveTransferToRelayChain>,
        ( /* ... */ ),
    >,
>;
```

### Proof of Concept
xcm-emulator integration test plan (in `integration-tests/emulated/tests/assets/asset-hub-polkadot/src/tests/reserve_transfer.rs`):
1. Fund `AssetHubPolkadotSender` with DOT.
2. From the signed origin, call `PolkadotXcm::execute` with a top-level program such as:
   `Xcm(vec![WithdrawAsset((Parent, amount).into()), SetAppendix(Xcm(vec![DepositReserveAsset { assets: Wild(All), dest: Parent.into(), xcm: Xcm(vec![]) }])), ClearOrigin])`.
3. Assert that execution either fails with a `Barrier`/`Filtered`-style error (expected/patched behavior) or, on the unpatched runtime, assert that the DOT balance moved to the Relay Chain sovereign/beneficiary account, proving the deny filter was bypassed:
   ```rust
   assert_err!(result, /* expected Barrier rejection */);
   // On unpatched runtime this assertion instead observes a successful transfer to Parent,
   // demonstrating the DenyReserveTransferToRelayChain bypass via nested SetAppendix.
   ```
4. Repeat with `SetErrorHandler` in place of `SetAppendix`, and with the reserve instruction (`InitiateReserveWithdraw`/`DepositReserveAsset`) nested at various depths, asserting the invariant holds (rejected) at every depth once `DenyRecursively` is applied, and fails (accepted) without it.

### Citations

**File:** system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs (L374-377)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyReserveTransferToRelayChain,
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

**File:** system-parachains/bulletin/bulletin-polkadot/src/xcm_config.rs (L147-150)
```rust
pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyRecursively<DenyReserveTransferToRelayChain>,
		(
```
