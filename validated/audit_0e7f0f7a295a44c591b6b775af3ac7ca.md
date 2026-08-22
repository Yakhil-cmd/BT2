### Title
Post-validation mutation of receipts (added `output_data_receivers`, yield/data payload) can push encoded receipt size above `max_receipt_size`, bypassing the enforced size limit - (File: `core/primitives/src/receipt.rs`, `runtime/runtime/src/verifier.rs`)

### Summary
`validate_receipt` in `runtime/runtime/src/verifier.rs` checks `borsh::object_length(receipt)` against `limit_config.max_receipt_size` only in `ValidateReceiptMode::NewReceipt` mode, at the moment a receipt is first created. However, some receipt fields (e.g. `output_data_receivers` on an `ActionReceipt`, or yield/resume payloads) are appended or mutated *after* this check, so the final serialized `Receipt` stored/forwarded can exceed `max_receipt_size`. This is a confirmed, already-tracked bug (referenced in-code as `nearcore#12606`) with partial mitigations added in `runtime/runtime/src/congestion_control.rs`.

### Finding Description
`validate_receipt` (`runtime/runtime/src/verifier.rs:527-542`) computes `borsh::object_length(receipt)` and rejects the receipt if it exceeds `limit_config.max_receipt_size`, but only when `mode == ValidateReceiptMode::NewReceipt`. [1](#0-0) 

The `ValidateReceiptMode::ExistingReceipt` variant explicitly documents that it must tolerate previously-created oversized receipts precisely because of this bug: [2](#0-1) 

An attacker-controlled contract, via `promise_batch_action_*`/`promise_then`/`promise_return`/`promise_yield_create`/`promise_yield_resume` host calls, can construct a promise DAG where a receipt is created at (or near) `max_receipt_size` and passes `NewReceipt` validation, but is subsequently mutated by the runtime (e.g. `output_data_receivers` appended when a downstream promise is attached via `promise_return`, or a yield/resume data payload attached) causing the final borsh-encoded `Receipt` to exceed `max_receipt_size` before it is persisted or sent cross-shard. Because the size check already passed at creation time and there is no re-validation after the mutation, the invariant "receipt encoded size ≤ `max_receipt_size`" is violated.

`compute_receipt_size` in `runtime/runtime/src/congestion_control.rs:964-967` is the function used for congestion accounting, and its caller `try_forward` (lines 397-427) contains an explicit comment acknowledging that receipts larger than the limit can exist and clamps the accounted size to `max_receipt_size` to avoid receipts getting permanently stuck in the outgoing buffer — this is a workaround, not a fix, and it means the true byte cost of forwarding/storing the oversized receipt is under-accounted relative to its real size. [3](#0-2) [4](#0-3) 

This exact scenario is reproduced by existing integration tests `test_max_receipt_size_promise_return` and `test_max_receipt_size_value_return` in `test-loop-tests/src/tests/max_receipt_size.rs`, which explicitly state the receipt ends up bigger than `max_receipt_size` due to this known bug and assert that an oversized receipt does occur on-chain (`assert_oversized_receipt_occurred`). [5](#0-4) [6](#0-5) 

### Impact Explanation
Because gas/storage costs for cross-shard receipt transmission and storage proof are computed per-byte at receipt-creation time (before the oversized mutation), a receipt whose true encoded size exceeds `max_receipt_size` is charged/accounted as if it were at most `max_receipt_size`. This allows an attacker to get bytes transmitted/stored effectively for free above the intended cap, increasing state-witness size, storage-proof size, and per-shard bandwidth beyond the protocol's designed 17 MiB `ChunkStateWitness` budget (see `docs/misc/state_witness_size_limits.md`). Repeated abuse increases computational/bandwidth cost for validators without matching gas charges — matching the "greatly increasing the computational cost of the network (free or underpriced execution)" High-severity impact class. [7](#0-6) 

### Likelihood Explanation
This is fully reachable by an unprivileged account: deploy an arbitrary contract and call it via `FunctionCall` actions using standard `promise_batch_action_*`/`promise_then`/`promise_return`/yield-resume host functions available to any contract — no special privileges required. It is deterministically reproducible, as demonstrated by the existing tests in `test-loop-tests/src/tests/max_receipt_size.rs`, which already construct receipts at exactly `max_receipt_size` and then trigger post-validation mutations (`output_data_receivers` addition via `promise_return`, or large value return via a data receipt) to push them over the limit.

### Recommendation
Re-validate (or re-check size of) a receipt after all mutations are applied and before it is persisted/queued/forwarded — i.e., call the `ReceiptValidationError::ReceiptSizeExceeded` check again at the final point where `output_data_receivers`, yield/resume payloads, or any other post-creation field is set, not only immediately after initial construction in `NewReceipt` mode. Alternatively, restructure receipt construction so all size-affecting fields (including `output_data_receivers`) are finalized before the `NewReceipt` validation is performed, and have `compute_receipt_size`/`try_forward` in `runtime/runtime/src/congestion_control.rs` reject (rather than clamp) any receipt found to be truly oversized, closing the "clamp to `max_receipt_size`" workaround referenced at `runtime/runtime/src/congestion_control.rs:413-427`.

### Proof of Concept
Existing tests already validate this exact defect end-to-end:
- `test_max_receipt_size_promise_return` in `test-loop-tests/src/tests/max_receipt_size.rs:130-208`: builds a promise DAG `A -> B`, where executing `A` creates promise `C` and does `promise_return`; adding `output_data_receivers` to `C`'s receipt after it already reached `max_receipt_size` pushes it over the limit, and `assert_oversized_receipt_occurred` confirms an on-chain receipt exceeded `max_receipt_size`.
- `test_max_receipt_size_value_return` in `test-loop-tests/src/tests/max_receipt_size.rs:216-267`: returns a value equal to `max_receipt_size`, which gets wrapped into a `DataReceipt` that becomes larger than the limit, again confirmed via `assert_oversized_receipt_occurred`.

To validate per the question's suggested fast-path, add an analogous case to `runtime/runtime/src/tests/apply.rs` that constructs a receipt at the size boundary, triggers the post-validation mutation path (e.g. via `promise_return`/output data receiver attachment), and assert with `cargo test -p node-runtime --features test_features` that `borsh::object_length` of the resulting persisted/forwarded receipt exceeds `limit_config.max_receipt_size` while the balance checker/gas totals show no additional charge for the excess bytes.

### Citations

**File:** runtime/runtime/src/verifier.rs (L533-542)
```rust
    if mode == ValidateReceiptMode::NewReceipt {
        let receipt_size: u64 =
            borsh::object_length(receipt).unwrap().try_into().expect("Can't convert usize to u64");
        if receipt_size > limit_config.max_receipt_size {
            return Err(ReceiptValidationError::ReceiptSizeExceeded {
                size: receipt_size,
                limit: limit_config.max_receipt_size,
            });
        }
    }
```

**File:** runtime/runtime/src/verifier.rs (L578-586)
```rust
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

**File:** runtime/runtime/src/congestion_control.rs (L413-427)
```rust
        // There is a bug which allows to create receipts that are above the size limit. Receipts
        // above the size limit might not fit under the maximum outgoing size limit. Let's pretend
        // that all receipts are at most `max_receipt_size` to avoid receipts getting stuck.
        // See https://github.com/near/nearcore/issues/12606
        let max_receipt_size = apply_state.config.wasm_config.limit_config.max_receipt_size;
        if size > max_receipt_size {
            tracing::debug!(
                target: "runtime",
                receipt_id=?receipt.receipt_id(),
                size,
                max_receipt_size,
                "try_forward observed a receipt with size exceeding the size limit",
            );
            size = max_receipt_size;
        }
```

**File:** runtime/runtime/src/congestion_control.rs (L964-967)
```rust
pub(crate) fn compute_receipt_size(receipt: &Receipt) -> Result<u64, IntegerOverflowError> {
    let size = borsh::object_length(&receipt).unwrap();
    size.try_into().map_err(|_| IntegerOverflowError)
}
```

**File:** test-loop-tests/src/tests/max_receipt_size.rs (L124-128)
```rust
// A function call will generate a new receipt. Size of this receipt will be equal to
// `max_receipt_size`, it'll pass validation, but then `output_data_receivers` will be modified and
// the receipt's size will go above max_receipt_size. The receipt should be rejected, but currently
// isn't because of a bug (See https://github.com/near/nearcore/issues/12606)
// Runtime shouldn't die when it encounters a receipt with size above `max_receipt_size`.
```

**File:** test-loop-tests/src/tests/max_receipt_size.rs (L210-213)
```rust
/// Return a value that is as large as max_receipt_size. The value will be wrapped in a data receipt
/// and the data receipt will be bigger than max_receipt_size. The receipt should be rejected, but
/// currently isn't because of a bug (See https://github.com/near/nearcore/issues/12606)
/// Creates the following promise DAG:
```

**File:** docs/misc/state_witness_size_limits.md (L1-18)
```markdown
## State witness size limits

Some limits were introduced to keep the size of `ChunkStateWitness` reasonable.
`ChunkStateWitness` contains all the incoming transactions and receipts that will be processed during chunk application and in theory a single receipt could be tens of megabytes in size. Distributing a `ChunkStateWitness` this large would be troublesome, so we limit the size and number of transactions, receipts, etc. The limits aim to keep the total uncompressed size of `ChunkStateWitness` under 17MiB.

There are two types of size limits:

* Hard limit - the size must be below this limit, anything else is considered invalid
* Soft limit - things are added until the limit is exceeded, after that things stop being added. The last added thing is allowed to slightly exceed the limit.

The limits are:

* `max_transaction_size = 1.5 MiB`
  * All transactions must be below 1.5 MiB, otherwise they'll be considered invalid and rejected.
  * Previously was 4MiB, now reduced to 1.5MiB
* `max_receipt_size - 4 MiB`:
  * All receipts must be below 4 MiB, otherwise they'll be considered invalid and rejected.
  * Previously there was no limit on receipt size. Set to 4MiB, might be reduced to 1.5MiB in the future to match the transaction limit.
```
