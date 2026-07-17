Looking at the actual `resolve_promise_yield_timeouts` implementation and its call site, I can trace the exact behavior under compute pressure.

**Key code path:**

`process_receipts` (line 2638-2640) calls `resolve_promise_yield_timeouts` **after** all local, delayed, and incoming receipts are processed. By that point, `total.compute` already reflects all prior receipt processing. [1](#0-0) 

The loop guard `if total.compute >= compute_limit` uses the **shared** compute accumulator from the entire chunk. If prior receipts exhausted the budget, the loop breaks on the very first iteration — no expired yields are dequeued, no `first_index` is advanced, no queue entries are removed. [2](#0-1) 

`first_index` is only incremented inside the loop body, after the entry is removed. An early break leaves the expired entries in state with `first_index` unchanged.

**The race window:** `resolve_promise_yield_timeouts` runs last in `process_receipts`. Any `PromiseResume` receipt arriving as an **incoming receipt** in the next block is processed in step 3 (incoming receipts), **before** `resolve_promise_yield_timeouts` runs in step 4. The code itself acknowledges this ordering: [3](#0-2) 

The deduplication guard at line 2972 (`contains_key(&promise_yield_key)`) only skips the timeout receipt if the yield was already resolved. If the attacker's `yield_resume` receipt arrives and is processed first in block H+1, it removes the `PromiseYieldReceipt` key — so when `resolve_promise_yield_timeouts` runs, `contains_key` returns false and no `Failed` resume is emitted. [4](#0-3) 

---

### Title
Compute-limit early break in `resolve_promise_yield_timeouts` allows attacker to resume expired yields with arbitrary data — (`runtime/runtime/src/lib.rs`)

### Summary
When chunk compute is exhausted by other receipts at block H, `resolve_promise_yield_timeouts` breaks before processing expired `PromiseYield` entries. In block H+1, an attacker who knows the `data_id` can submit a `yield_resume` transaction that is processed as an incoming receipt **before** the deferred timeout loop runs, causing the yield callback to receive `PromiseResult::Successful(attacker_payload)` instead of `PromiseResult::Failed`.

### Finding Description
`resolve_promise_yield_timeouts` shares the `total.compute` accumulator with all prior receipt processing in the same chunk. [5](#0-4) 

If `total.compute >= compute_limit` on entry to the loop (because local/delayed/incoming receipts already saturated the budget), the while-loop breaks immediately: [6](#0-5) 

Entries with `expires_at <= block_height` remain in the `PromiseYieldTimeout` queue with `first_index` unchanged. In the next block, incoming receipts are processed before `resolve_promise_yield_timeouts`: [7](#0-6) 

An attacker-submitted `PromiseResume` receipt (via `promise_yield_resume` host function) arrives as an incoming receipt, is processed first, removes the `PromiseYieldReceipt` trie key, and delivers `data: Some(attacker_bytes)` to the callback. When `resolve_promise_yield_timeouts` subsequently runs, `contains_key` returns false and no `Failed` resume is generated. [8](#0-7) 

### Impact Explanation
The exact corrupted value is `promise_result[0]` in the yield callback: it becomes `PromiseResult::Successful(attacker_payload)` instead of `PromiseResult::Failed`. Any contract that uses the timeout as a trust boundary — e.g., to trigger a refund, cancel an escrow, or enforce a deadline — can be manipulated. The attacker controls the callback input for a yield they created, bypassing the `yield_timeout_length_in_blocks` guarantee.

### Likelihood Explanation
The attacker must:
1. Create a `PromiseYield` in their own contract (they know the `data_id`).
2. At the timeout block H, submit enough compute-heavy transactions to saturate the chunk's compute budget before `resolve_promise_yield_timeouts` runs.
3. In block H+1, submit a `yield_resume` transaction with chosen payload.

Step 2 requires spending gas proportional to the chunk gas limit (~1 Tgas), which is costly but not prohibitive on mainnet. The attack window is exactly one block. The attacker must time the congestion precisely to block H, which is predictable since `expires_at` is set at yield creation time.

### Recommendation
- Do not share `total.compute` between regular receipt processing and `resolve_promise_yield_timeouts`. Give the timeout loop a dedicated, unconditional compute budget (or no limit at all, since the number of expired yields per block is bounded by `yield_timeout_length_in_blocks` and the per-block yield creation rate).
- Alternatively, process `resolve_promise_yield_timeouts` **before** incoming receipts so that the timeout always wins the race.
- Add a protocol-level invariant check: if `queue_entry.expires_at <= block_height` and the yield is still in state, the timeout receipt must be emitted regardless of compute pressure.

### Proof of Concept
A test-loop test would:
1. Deploy a contract that calls `promise_yield_create` with `timeout = T` blocks.
2. At block `yield_create_height + T`, inject 25+ compute-saturating function calls (as in the existing `create_congestion` helper) to exhaust the chunk compute budget. [9](#0-8) 

3. Assert that `resolve_promise_yield_timeouts` emits zero `PromiseResume` receipts at block H (timeout deferred).
4. In block H+1, submit a `yield_resume` transaction with `data = b"attacker"` before the block is produced.
5. Assert that the callback receives `PromiseResult::Successful(b"attacker")` rather than `PromiseResult::Failed`, and that the `PromiseYieldReceipt` trie key is absent after block H+1.

### Citations

**File:** runtime/runtime/src/lib.rs (L2630-2640)
```rust
        // And then we process the new incoming receipts. These are receipts from other shards.
        self.process_incoming_receipts(
            processing_state,
            receipt_sink,
            compute_limit,
            &mut validator_proposals,
        )?;

        // Resolve timed-out PromiseYield receipts
        let promise_yield_result =
            resolve_promise_yield_timeouts(processing_state, receipt_sink, compute_limit)?;
```

**File:** runtime/runtime/src/lib.rs (L2935-2936)
```rust
    let mut state_update = &mut processing_state.state_update;
    let total = &mut processing_state.total;
```

**File:** runtime/runtime/src/lib.rs (L2946-2949)
```rust
    while promise_yield_indices.first_index < promise_yield_indices.next_available_index {
        if total.compute >= compute_limit || state_update.trie.check_proof_size_limit_exceed() {
            break;
        }
```

**File:** runtime/runtime/src/lib.rs (L2967-2972)
```rust
        // Check if the yielded promise still needs to be resolved
        let promise_yield_key = TrieKey::PromiseYieldReceipt {
            receiver_id: queue_entry.account_id.clone(),
            data_id: queue_entry.data_id,
        };
        if state_update.contains_key(&promise_yield_key, AccessOptions::DEFAULT)? {
```

**File:** runtime/runtime/src/lib.rs (L3009-3013)
```rust
            // The receipt is destined for the local shard and will be placed in the outgoing
            // receipts buffer. It is possible that there is already an outgoing receipt resolving
            // this yield if `yield_resume` was invoked by some receipt which was processed in
            // the current chunk. The ordering will be maintained because the receipts are
            // destined for the same shard; the timeout will be processed second and discarded.
```

**File:** runtime/runtime/src/lib.rs (L3021-3024)
```rust
        processed_yield_timeouts.push(queue_entry);
        state_update.remove(queue_entry_key);
        // Math checked above: first_index is less than next_available_index
        promise_yield_indices.first_index += 1;
```

**File:** test-loop-tests/src/tests/yield_timeouts.rs (L312-332)
```rust
fn create_congestion(env: &TestLoopEnv) {
    let signer = create_user_test_signer(&AccountId::from_str("test0").unwrap());
    let genesis_block = env.validator().client().chain.get_block_by_height(0).unwrap();

    for i in 0..25 {
        let signed_transaction = SignedTransaction::from_actions(
            i + 100,
            "test0".parse().unwrap(),
            "test0".parse().unwrap(),
            &signer,
            vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: "epoch_height".to_string(),
                args: vec![],
                gas: Gas::from_gas(100),
                deposit: Balance::ZERO,
            }))],
            *genesis_block.hash(),
        );
        env.validator().submit_tx(signed_transaction);
    }
}
```
