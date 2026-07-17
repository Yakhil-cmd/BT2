### Title
Unmetered Linear Iteration over Expired PromiseYield Timeouts in `resolve_promise_yield_timeouts` Bypasses Chunk Compute Limit — (File: `runtime/runtime/src/lib.rs`)

### Summary

`resolve_promise_yield_timeouts` iterates over every expired `PromiseYieldTimeout` queue entry in a single chunk application without ever updating the shared `total.compute` counter inside the loop. The compute-limit guard at the top of the loop is therefore permanently ineffective for this phase: once the loop starts below the limit, it stays below the limit for every subsequent iteration. An unprivileged user who accumulates many `promise_yield_create` calls across blocks — all set to expire at the same block height — can force unbounded unmetered work into a single chunk, breaking the protocol's invariant that chunk processing is bounded by the gas/compute limit.

### Finding Description

`resolve_promise_yield_timeouts` is called at the end of `process_receipts`, after `process_local_receipts`, `process_delayed_receipts`, and `process_incoming_receipts` have all respected the compute limit. [1](#0-0) 

Inside `resolve_promise_yield_timeouts`, the loop guard is:

```rust
while promise_yield_indices.first_index < promise_yield_indices.next_available_index {
    if total.compute >= compute_limit || state_update.trie.check_proof_size_limit_exceed() {
        break;
    }
    // ... reads trie, creates PromiseResume receipt, calls forward_or_buffer_receipt ...
    promise_yield_indices.first_index += 1;
}
``` [2](#0-1) 

`total` is a `TotalResourceGuard` whose `compute` field is only incremented via `total.add(gas_burnt, compute_usage)`. [3](#0-2) 

`total.add` is never called anywhere inside `resolve_promise_yield_timeouts`. The loop body performs multiple trie reads (`get::<PromiseYieldTimeout>`, `contains_key`, `get_pure`), constructs a `PromiseResume` receipt, and calls `forward_or_buffer_receipt` — all without incrementing `total.compute`. The compute-limit check therefore evaluates the same stale value on every iteration and never triggers a break due to work done within the loop itself. [4](#0-3) 

The `PromiseYieldTimeout` queue is a persistent trie-backed FIFO keyed by `TrieKey::PromiseYieldTimeout { index }`, ordered by `expires_at`. [5](#0-4) [6](#0-5) 

Entries are enqueued via `enqueue_promise_yield_timeout` whenever a contract calls the `promise_yield_create` host function. [7](#0-6) 

There is no protocol-level cap on the total number of pending `PromiseYieldTimeout` entries.

### Impact Explanation

An attacker who creates N `PromiseYield` receipts all expiring at block height H forces `resolve_promise_yield_timeouts` to perform O(N) trie reads, receipt constructions, and `forward_or_buffer_receipt` calls in the single chunk applied at height H, with zero compute charged against the chunk's compute limit. This work is entirely outside the metered budget. Depending on N, this can cause the chunk producer to significantly overrun its slot time, causing missed chunks and shard disruption — the exact analog of the permissionless chain-halt described in the external report.

### Likelihood Explanation

Any unprivileged account can deploy a contract that calls `promise_yield_create` in a loop. Each call costs gas, so the attacker pays per yield created, but the cost is spread across many blocks (up to `yield_timeout_length_in_blocks` blocks of accumulation). The attack is permissionless and the cost scales linearly with the number of yields, while the damage (unmetered chunk processing time) also scales linearly. The existing `check_proof_size_limit_exceed()` guard provides partial mitigation only if the accumulated trie proof size for all timeout entries exceeds the proof size limit before the loop finishes — which is not guaranteed for small entries.

### Recommendation

Inside `resolve_promise_yield_timeouts`, charge compute for each iteration's work before or after processing each entry, using the same `total.add(...)` mechanism used by the rest of chunk processing. A minimal fix is to assign a fixed compute cost per timeout entry (analogous to the cost of processing a small receipt) and call `total.add(per_timeout_compute, per_timeout_compute)` at the bottom of the loop body, so the compute-limit check at the top of the next iteration can actually fire.

### Proof of Concept

1. Deploy a contract on shard S that, when called, invokes `promise_yield_create` in a loop (up to the per-chunk gas limit), returning a promise that will never be resumed.
2. Submit transactions calling this contract across many consecutive blocks, accumulating N `PromiseYieldTimeout` entries in the trie, all with `expires_at = H` for some future block height H.
3. At block height H, `resolve_promise_yield_timeouts` is called. `total.compute` entering the function reflects only the work done by prior receipt processing phases. The loop iterates over all N entries without updating `total.compute`, performing N trie reads of `PromiseYieldTimeout`, N `contains_key` checks, N `PromiseResume` receipt constructions, and N `forward_or_buffer_receipt` calls — all unmetered.
4. The chunk producer for shard S at height H spends wall-clock time proportional to N on this unmetered work, potentially missing its slot.

The only partial guard is `check_proof_size_limit_exceed()`, which may break the loop early if the cumulative trie proof for all N entries exceeds the proof size limit — but this is not guaranteed and depends on entry size and the configured limit. [8](#0-7) [9](#0-8)

### Citations

**File:** runtime/runtime/src/lib.rs (L2638-2640)
```rust
        // Resolve timed-out PromiseYield receipts
        let promise_yield_result =
            resolve_promise_yield_timeouts(processing_state, receipt_sink, compute_limit)?;
```

**File:** runtime/runtime/src/lib.rs (L2930-3025)
```rust
fn resolve_promise_yield_timeouts(
    processing_state: &mut ApplyProcessingReceiptState,
    receipt_sink: &mut ReceiptSink,
    compute_limit: u64,
) -> Result<ResolvePromiseYieldTimeoutsResult, RuntimeError> {
    let mut state_update = &mut processing_state.state_update;
    let total = &mut processing_state.total;
    let apply_state = &processing_state.apply_state;

    let mut promise_yield_indices: PromiseYieldIndices =
        get(state_update, &TrieKey::PromiseYieldIndices)?.unwrap_or_default();
    let initial_promise_yield_indices = promise_yield_indices.clone();
    let mut new_receipt_index: usize = 0;

    let mut processed_yield_timeouts = vec![];
    let yield_processing_start = std::time::Instant::now();
    while promise_yield_indices.first_index < promise_yield_indices.next_available_index {
        if total.compute >= compute_limit || state_update.trie.check_proof_size_limit_exceed() {
            break;
        }

        let queue_entry_key =
            TrieKey::PromiseYieldTimeout { index: promise_yield_indices.first_index };

        let queue_entry =
            get::<PromiseYieldTimeout>(state_update, &queue_entry_key)?.ok_or_else(|| {
                StorageError::StorageInconsistentState(format!(
                    "PromiseYield timeout queue entry #{} should be in the state",
                    promise_yield_indices.first_index
                ))
            })?;

        // Queue entries are ordered by expires_at
        if queue_entry.expires_at > apply_state.block_height {
            break;
        }

        // Check if the yielded promise still needs to be resolved
        let promise_yield_key = TrieKey::PromiseYieldReceipt {
            receiver_id: queue_entry.account_id.clone(),
            data_id: queue_entry.data_id,
        };
        if state_update.contains_key(&promise_yield_key, AccessOptions::DEFAULT)? {
            let new_receipt_id = create_receipt_id_from_receipt_id(
                &queue_entry.data_id,
                apply_state.block_height,
                new_receipt_index,
            );
            new_receipt_index += 1;

            // Create a PromiseResume receipt to resolve the timed-out yield.
            let resume_receipt = Receipt::V0(ReceiptV0 {
                predecessor_id: queue_entry.account_id.clone(),
                receiver_id: queue_entry.account_id.clone(),
                receipt_id: new_receipt_id,
                receipt: ReceiptEnum::PromiseResume(DataReceipt {
                    data_id: queue_entry.data_id,
                    data: None,
                }),
            });

            // Record a ReceiptToTx entry for the new resume receipt. The parent is the
            // yield receipt that is being timed out.
            if processing_state.apply_state.save_receipt_to_tx {
                let yield_receipt: Receipt = get_pure(state_update, &promise_yield_key)?
                    .expect("promise yield receipt should exist since contains_key was true");
                processing_state.receipt_to_tx.push((
                    new_receipt_id,
                    ReceiptToTxInfo::V1(ReceiptToTxInfoV1 {
                        origin: ReceiptOrigin::FromReceipt(ReceiptOriginReceipt {
                            parent_receipt_id: *yield_receipt.receipt_id(),
                            parent_predecessor_id: yield_receipt.predecessor_id().clone(),
                        }),
                        receiver_account_id: queue_entry.account_id.clone(),
                        shard_id: processing_state.apply_state.shard_id,
                    }),
                ));
            }

            // The receipt is destined for the local shard and will be placed in the outgoing
            // receipts buffer. It is possible that there is already an outgoing receipt resolving
            // this yield if `yield_resume` was invoked by some receipt which was processed in
            // the current chunk. The ordering will be maintained because the receipts are
            // destined for the same shard; the timeout will be processed second and discarded.
            receipt_sink.forward_or_buffer_receipt(
                resume_receipt,
                apply_state,
                &mut state_update,
            )?;
        }

        processed_yield_timeouts.push(queue_entry);
        state_update.remove(queue_entry_key);
        // Math checked above: first_index is less than next_available_index
        promise_yield_indices.first_index += 1;
    }
```

**File:** runtime/runtime/src/lib.rs (L3052-3057)
```rust
impl TotalResourceGuard {
    fn add(&mut self, gas: u64, compute: u64) -> Result<(), IntegerOverflowError> {
        self.gas = self.gas.checked_add(gas).ok_or(IntegerOverflowError)?;
        self.compute = safe_add_compute(self.compute, compute)?;
        Ok(())
    }
```

**File:** core/primitives/src/trie_key.rs (L237-241)
```rust
    /// Used to store the element at given index `u64` in the PromiseYield timeout queue.
    /// The queue is unique per shard.
    PromiseYieldTimeout {
        index: u64,
    } = col::PROMISE_YIELD_TIMEOUT,
```

**File:** core/primitives/src/receipt.rs (L1082-1091)
```rust
/// Entries in the queue of PromiseYield timeouts.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Debug, ProtocolSchema)]
pub struct PromiseYieldTimeout {
    /// The account on which the yielded promise was created
    pub account_id: AccountId,
    /// The `data_id` used to identify the awaited input data
    pub data_id: CryptoHash,
    /// The block height before which the data must be submitted
    pub expires_at: BlockHeight,
}
```

**File:** core/store/src/utils/mod.rs (L163-180)
```rust
// Enqueues given timeout to the PromiseYield timeout queue
pub fn enqueue_promise_yield_timeout(
    state_update: &mut TrieUpdate,
    promise_yield_indices: &mut PromiseYieldIndices,
    account_id: AccountId,
    data_id: CryptoHash,
    expires_at: BlockHeight,
) {
    set(
        state_update,
        TrieKey::PromiseYieldTimeout { index: promise_yield_indices.next_available_index },
        &PromiseYieldTimeout { account_id, data_id, expires_at },
    );
    promise_yield_indices.next_available_index = promise_yield_indices
        .next_available_index
        .checked_add(1)
        .expect("Next available index for PromiseYield timeout queue exceeded the integer limit");
}
```
