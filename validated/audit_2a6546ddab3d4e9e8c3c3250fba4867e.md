## Analog Found: Deterministic node panic when a queued/incoming receipt fails validation on execution — same "unrecoverable sequential-queue" bug class as `BridgedGovernor`

### Title
Deterministic node panic on `StorageInconsistentState`/`ReceiptValidationError` for delayed or incoming receipts causes an unrecoverable chain stall - (File: `runtime/runtime/src/lib.rs`, `chain/chain/src/runtime/mod.rs`)

### Summary
The `BridgedGovernor` bug is a class of vulnerability where a strictly-ordered, FIFO message queue (sequential LZ nonce) has no way to skip or recover from one non-executable entry, permanently freezing all future processing — including the only channel that could deliver a fix. nearcore has a structurally analogous FIFO receipt queue (the delayed-receipt queue processed in strict index order) whose entries are re-validated at execution time with `ValidateReceiptMode::ExistingReceipt`. If validation ever fails for an already-queued (or incoming) receipt, the runtime does not skip or discard it — it surfaces `StorageError::StorageInconsistentState` / `RuntimeError::ReceiptValidationError`, and the calling code in `chain/chain/src/runtime/mod.rs::apply_chunk` explicitly `panic!`s on that error class. Because every validator/RPC node deterministically re-executes the same chunk, this is not a single-node crash but a chain-wide, unrecoverable stall — the same "no way to unstick the sequential queue" failure mode described in the report.

### Finding Description
The delayed-receipt queue is a persistent, strictly FIFO structure: receipts are appended at `next_available_index` and popped from `first_index`, and popping/processing order can never be reordered or skipped [1](#0-0) .

When a delayed receipt is popped, it is re-validated with `ValidateReceiptMode::ExistingReceipt`; any validation failure is deliberately converted into a `StorageError::StorageInconsistentState` and propagated as an error (not silently skipped): [2](#0-1) 

The same pattern exists for newly arrived incoming (cross-shard) receipts — they are validated in `ExistingReceipt` mode specifically so invalid receipts are never persisted as delayed, but a failure here returns `RuntimeError::ReceiptValidationError` instead of being dropped: [3](#0-2) 

Both error variants are handled fatally by the chain layer. `RuntimeError::ReceiptValidationError` is turned into a hard `panic!` unconditionally, and `RuntimeError::StorageError` wrapping `StorageInconsistentState` is caught by the generic `_ => panic!("{err}")` branch in `apply_chunk`: [4](#0-3) [5](#0-4) 

The `ExistingReceipt` mode was explicitly introduced to be *more lenient* than `NewReceipt` mode precisely because a prior production bug (near/nearcore#12606) allowed oversized receipts to be created and later stored as delayed, and the runtime needed to tolerate them retroactively rather than panic on every future block that tries to process the backlog: [6](#0-5) 

This is the direct structural analog of the `BridgedGovernor.lzReceive` bug: a strictly ordered queue (LZ nonce vs. delayed-receipt index) that must process entries one-by-one, where a single entry that becomes non-executable/invalid at execution time has no recovery path other than a hard fork/binary patch — the runtime cannot simply "skip" the bad delayed receipt at index `first_index` because doing so would mean different nodes diverge in what they choose to skip, and the current code intentionally treats any residual validation failure as fatal rather than recoverable.

### Impact Explanation
If any accepted transaction/receipt can produce a receipt that (a) passes `NewReceipt` validation at creation time (so it is admitted into the local/incoming/delayed pipeline), but (b) fails `ExistingReceipt` validation when it is later popped from the delayed queue (e.g., due to a future protocol-version-dependent validation rule tightening, or a validation gap not covered by the deliberately-loosened `ExistingReceipt` checks), then every node that applies that chunk will panic. Because block/chunk application is deterministic and mandatory for all validators tracking the shard, this results in a full chain stall for that shard — not a "malicious node" issue, but a consensus-halting condition triggered by ordinary transaction/receipt submission. Unlike `BridgedGovernor`, nearcore can recover via a coordinated software patch and re-sync, but until that happens, the affected shard makes no progress, which is the "irreparable state" impact class called out in the report (chain stall).

### Likelihood Explanation
This exact bug class has already manifested once in production (near/nearcore#12606: a bug allowed receipts larger than `max_receipt_size` to be created and stored as delayed, and the runtime had to be patched with the more-lenient `ExistingReceipt` mode specifically to avoid panicking when finally processing them). This demonstrates the pathway is real and reachable from ordinary transaction/contract-call activity, not merely theoretical. The residual risk is that `ExistingReceipt`'s leniency is scoped to known past discrepancies (size limit) — any future validation rule added to `validate_action_receipt`/`validate_data_receipt`/`validate_actions_with_mode` that is enforced in both modes, or any new discrepancy introduced by a protocol upgrade that changes receipt semantics for already-queued receipts, reintroduces the same fatal-panic path with no built-in recovery.

### Recommendation
Treat validation failures for already-admitted delayed/incoming receipts as a per-receipt execution failure (producing a failed `ExecutionOutcome`, similar to how a contract-level revert is handled) rather than a hard `panic!`/fatal `RuntimeError`, so a single bad queue entry cannot deterministically halt the shard. At minimum, ensure any new validation rule added to `validate_receipt` is version-gated so it can never apply retroactively to receipts already persisted before the rule existed, and treat `ExistingReceipt` mode as strictly append-only in terms of allowed leniency (never re-tightened) to guarantee already-delayed receipts remain processable indefinitely, analogous to the recommended "allow unordered/skippable processing" fix in the `BridgedGovernor` report.

### Proof of Concept
1. Under protocol version `N`, submit a transaction/contract call that produces an action receipt satisfying all `validate_action_receipt`/`validate_actions_with_mode` checks under `NewReceipt` mode at version `N` (i.e., it is accepted and, due to congestion/gas limits, gets pushed onto the delayed-receipt queue per `docs/RuntimeSpec/Components/RuntimeCrate.md` lines 76-83).
2. Advance the chain to protocol version `N+1`, which introduces a new receipt/action validation rule enforced by both `NewReceipt` and `ExistingReceipt` modes (or a rule not covered by the `ExistingReceipt` leniency carve-out documented at `runtime/runtime/src/verifier.rs` lines 578-585).
3. When the shard's delayed-receipt queue reaches this entry (`process_delayed_receipts`, `runtime/runtime/src/lib.rs` lines 2443-2455), `validate_receipt(..., ExistingReceipt)` now fails against protocol version `N+1`, producing `StorageError::StorageInconsistentState`.
4. Every node applying this chunk hits the `_ => panic!("{err}")` branch in `chain/chain/src/runtime/mod.rs::apply_chunk` (lines 1264-1274), halting chunk/block production for that shard on all nodes simultaneously — a deterministic, unrecoverable chain stall until a software patch is deployed, mirroring the `BridgedGovernor` "no alternative recovery mechanism" failure mode.

### Citations

**File:** docs/RuntimeSpec/Components/RuntimeCrate.md (L76-83)
```markdown
### Delayed receipts

Delayed receipts are stored as a persistent queue in the state.
Initially, the first unprocessed index and the next available index are initialized to 0.
When a new delayed receipt is added, it's written under the next available index in to the state and the next available index is incremented by 1.
When a delayed receipt is processed, it's read from the state using the first unprocessed index and the first unprocessed index is incremented.
At the end of the receipt processing, the all remaining local and incoming receipts are considered to be delayed and stored to the state in their respective order.
If during receipt processing, we've changed indices, then the delayed receipt indices are stored to the state as well.
```

**File:** runtime/runtime/src/lib.rs (L2443-2455)
```rust
            // Validating the delayed receipt. If it fails, it's likely the state is inconsistent.
            validate_receipt(
                &processing_state.apply_state.config.wasm_config.limit_config,
                &receipt,
                protocol_version,
                ValidateReceiptMode::ExistingReceipt,
            )
            .map_err(|e| {
                StorageError::StorageInconsistentState(format!(
                    "Delayed receipt {:?} in the state is invalid: {}",
                    receipt, e
                ))
            })?;
```

**File:** runtime/runtime/src/lib.rs (L2508-2518)
```rust
        processing_state.outcomes.reserve(processing_state.incoming_receipts.len());
        for receipt in processing_state.incoming_receipts {
            // Validating new incoming no matter whether we have available gas or not. We don't
            // want to store invalid receipts in state as delayed.
            validate_receipt(
                &processing_state.apply_state.config.wasm_config.limit_config,
                receipt,
                protocol_version,
                ValidateReceiptMode::ExistingReceipt,
            )
            .map_err(RuntimeError::ReceiptValidationError)?;
```

**File:** chain/chain/src/runtime/mod.rs (L356-369)
```rust
            .map_err(|e| match e {
                RuntimeError::InvalidTxError(err) => {
                    tracing::warn!(?err, "invalid tx");
                    Error::InvalidTransactions
                }
                // TODO(#2152): process gracefully
                RuntimeError::UnexpectedIntegerOverflow(reason) => {
                    panic!("RuntimeError::UnexpectedIntegerOverflow {reason}")
                }
                RuntimeError::StorageError(e) => Error::StorageError(e),
                // TODO(#2152): process gracefully
                RuntimeError::ReceiptValidationError(e) => panic!("{}", e),
                RuntimeError::ValidatorError(e) => e.into(),
            })?;
```

**File:** chain/chain/src/runtime/mod.rs (L1264-1274)
```rust
        ) {
            Ok(result) => Ok(result),
            Err(e) => match e {
                Error::StorageError(err) => match &err {
                    StorageError::FlatStorageBlockNotSupported(_)
                    | StorageError::MissingTrieValue(..) => Err(err.into()),
                    _ => panic!("{err}"),
                },
                _ => Err(e),
            },
        }
```

**File:** runtime/runtime/src/verifier.rs (L573-586)
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidateReceiptMode {
    /// Used for validating new receipts that were just created.
    /// More strict than `OldReceipt` mode, which has to handle older receipts.
    NewReceipt,
    /// Used for validating older receipts that were saved in the state/received. Less strict than
    /// NewReceipt validation. Tolerates some receipts that wouldn't pass new validation. It has to
    /// be less strict because:
    /// 1) Older receipts might have been created before new validation rules.
    /// 2) There is a bug which allows to create receipts that are above the size limit. Runtime has
    ///    to handle them gracefully until the receipt size limit bug is fixed.
    ///    See https://github.com/near/nearcore/issues/12606 for details.
    ExistingReceipt,
}
```
