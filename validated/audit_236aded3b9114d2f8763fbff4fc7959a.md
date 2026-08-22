### Title
Receipts can exceed `max_receipt_size` enforced limit, undermining congestion/size accounting - (File: `runtime/runtime/src/congestion_control.rs`, related to `core/primitives/src/receipt.rs`)

### Summary
The runtime does not strictly enforce that a `Receipt` created via `promise_batch_action_*` host calls stays within `wasm_config.limit_config.max_receipt_size` before the receipt is committed to congestion accounting, buffers, or the delayed-receipt queue. The codebase itself explicitly acknowledges this as a known, unresolved bug (referenced inline as near/nearcore#12606) and works around it by *clamping* the observed size to `max_receipt_size` in `try_forward` and in bandwidth-request generation, rather than rejecting or preventing the oversized receipt at creation time.

### Finding Description
`compute_receipt_size` computes a receipt's congestion-relevant size via `borsh::object_length(&receipt)` [1](#0-0) , and this value is used to charge congestion/bandwidth accounting (`add_receipt_bytes`, buffer/outgoing limits) throughout `congestion_control.rs`. However, the enforcement of `max_receipt_size` at the point a receipt is *created* (from `promise_batch_action_*` host calls building up `ActionReceiptMetadata`/`Action` lists in `ReceiptManager`, see `runtime/runtime/src/receipt_manager.rs`) was not found to hard-reject receipts whose eventual borsh-encoded size exceeds `max_receipt_size`. Instead, the size-limit violation is handled reactively: in `ReceiptSinkV2::try_forward`, the code explicitly clamps an oversized receipt's `size` down to `max_receipt_size` before applying outgoing bandwidth limits, with an inline comment citing the known bug: [2](#0-1) 
The same clamping workaround is repeated in bandwidth-request generation: [3](#0-2) 
These comments demonstrate that the nearcore maintainers are already aware that receipts can be constructed above the size limit and that the current mitigation is a best-effort clamp for outgoing-bandwidth bookkeeping only — it does not prevent the oversized receipt from being created, stored, forwarded, or executed; it only prevents the bandwidth-scheduler request/limit math from stalling on it.

### Impact Explanation
An oversized receipt breaks the invariant that receipt encoded size is bounded and charged for congestion control and bandwidth scheduling purposes. Because congestion/bandwidth accounting under-charges size for receipts above `max_receipt_size` (the real cost is clamped down to the limit rather than reflecting the true encoded size), an attacker can cause the network to account for less size/bandwidth than is actually consumed by transmitting, storing, and processing such receipts across shards — a form of underpriced execution/storage relative to true resource consumption, matching the "greatly increasing the computational cost of the network (free or underpriced execution)" impact class.

### Likelihood Explanation
This is a pre-existing, acknowledged issue (tracked as near/nearcore#12606) rather than a newly discovered path; the exact conditions needed to construct a receipt exceeding `max_receipt_size` via `promise_batch_action_*` calls (e.g., combining many actions/large args/large method names in a single action receipt) are not fully enforced by a single hard limit check at receipt-assembly time in the code paths I was able to inspect (`runtime/runtime/src/receipt_manager.rs`). I was unable to locate the exact host-function-level limit check (if any) that near-vm-runner applies against `max_receipt_size` when appending actions, so I cannot confirm with full certainty whether construction of an over-limit receipt is currently possible end-to-end or whether an independent check elsewhere (e.g. total prepaid gas/args length limits) prevents it in practice. This should be verified further using a Devin session to inspect near-vm-runner logic (limit_config checks in `promise_batch_action_*` handlers) and confirm reachability.

### Recommendation
Enforce `max_receipt_size` as a hard limit at receipt-assembly time (e.g., in `ReceiptManager`/action-append host functions or the point where `ActionReceiptMetadata` is finalized into a `Receipt`), rejecting the transaction/host call with a deterministic error (e.g., a new `HostError`/`FunctionCallError`) rather than relying on later clamping in `try_forward` / bandwidth-request generation. Add an explicit unit test asserting `compute_receipt_size` (or the borsh-encoded receipt) never exceeds `wasm_config.limit_config.max_receipt_size` for any successfully created receipt.

### Proof of Concept
Extend `test-loop-tests/src/tests/max_receipt_size.rs` and/or `runtime/runtime/src/tests/apply.rs`:
1. Deploy an attacker contract that calls `promise_batch_action_function_call`/`promise_batch_create` repeatedly with maximally sized `method_name`/`args` payloads to accumulate a single `ActionReceiptMetadata` whose serialized size, once converted to `Receipt`/borsh-encoded, exceeds `apply_state.config.wasm_config.limit_config.max_receipt_size`.
2. Apply the resulting transaction through `Runtime::apply` and assert `compute_receipt_size(&receipt) <= max_receipt_size` fails (demonstrating the bypass), or, after a fix, assert the transaction/receipt creation is rejected with a deterministic error and gas/balance are still fully charged and consistent (`cargo test -p node-runtime --features test_features`).
3. Cross-check with `try_forward`'s clamping behavior — before a fix, the test should show the sink accepting/clamping an over-limit receipt instead of rejecting it outright at creation. [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** runtime/runtime/src/congestion_control.rs (L556-565)
```rust
        // There's a bug which allows to create receipts above `max_receipt_size` (https://github.com/near/nearcore/issues/12606).
        // This could cause problems with bandwidth scheduler which would generate requests for size above max size, and these
        // requests would never be fulfilled. For bandwidth requests let's pretend that all sizes are below `max_receipt_size`.
        // The same pretending logic is also present in `try_forward` which compares receipt size with outgoing limit.
        // This logic should also make it possible to do protocol upgrades that lower `max_receipt_size` without too much trouble.
        let sizes_iter = receipt_sizes_iter
            .map_ok(|group_size| std::cmp::min(group_size, params.max_receipt_size));

        // Create the bandwidth request based on buffered receipt (group) sizes
        BandwidthRequest::make_from_receipt_sizes(to_shard, sizes_iter, params)
```

**File:** runtime/runtime/src/congestion_control.rs (L943-967)
```rust
/// Get the receipt size from the receipt that was retrieved from the state.
/// If it is a [Receipt], the size will be computed.
/// If it s the [StateStoredReceipt], the size will be read from the metadata.
pub(crate) fn receipt_size(
    receipt: &ReceiptOrStateStoredReceipt,
) -> Result<u64, IntegerOverflowError> {
    match receipt {
        ReceiptOrStateStoredReceipt::Receipt(receipt) => compute_receipt_size(receipt),
        ReceiptOrStateStoredReceipt::StateStoredReceipt(receipt) => {
            Ok(receipt.metadata().congestion_size)
        }
    }
}

/// Calculate the size of a receipt before it is pushed into a state queue or
/// buffer. Please note that this method should only be used when storing
/// receipts into state. It should not be used for retrieving receipts from the
/// state.
///
/// The calculation is part of protocol and should only be modified with a
/// protocol upgrade.
pub(crate) fn compute_receipt_size(receipt: &Receipt) -> Result<u64, IntegerOverflowError> {
    let size = borsh::object_length(&receipt).unwrap();
    size.try_into().map_err(|_| IntegerOverflowError)
}
```
