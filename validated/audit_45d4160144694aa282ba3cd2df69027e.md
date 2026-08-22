### Title
Unmetered iteration over PromiseYield timeout queue allows cheap DoS/slowdown of chunk `apply()` - ([File: runtime/runtime/src/lib.rs])

### Summary
`resolve_promise_yield_timeouts()` walks the persistent PromiseYield timeout queue and, for every already-resolved (non-timeout) entry it finds, simply removes it from state and advances the queue cursor — without ever charging gas/compute for that work. This mirrors the reported `Voter::_processPendingRemovals()` bug class: a queue that a user can cheaply populate is drained by an internal loop whose only safety valve is a resource counter (`total.compute` / proof-size) that this same loop never increments for the "no-op" case, so an attacker-inflated backlog can be processed for free in a single chunk.

### Finding Description
`resolve_promise_yield_timeouts` iterates `promise_yield_indices.first_index .. next_available_index`, breaking only when: [1](#0-0) 

For each entry it checks whether the corresponding `PromiseYieldReceipt` still exists. If it does not (meaning the yield was already resolved via `promise_yield_resume` before its timeout), the code just records the entry, deletes the queue key, and advances `first_index` — with no call to `total.add(...)`: [2](#0-1) 

Compare this to the "resume needed" branch, where a new `PromiseResume` receipt is created and only *that* receipt's forwarding/execution gets charged gas elsewhere in the pipeline via `receipt_sink.forward_or_buffer_receipt`: [3](#0-2) 

Because `total.compute` is only advanced by other receipt-processing stages (local/delayed/incoming receipts) before this function runs, and this function itself never increments it for skipped entries, the loop's only real bound in the "all entries already resolved" case is `state_update.trie.check_proof_size_limit_exceed()` — a proof-*size* limit, not a compute/time limit. An attacker can:
1. Call `yield_create` many times across many blocks (bounded per block only by the normal gas limit, so this can be done cheaply over time and is fully paid for at creation).
2. Immediately call `promise_yield_resume` on each of them (also paid), which deletes `PromiseYieldReceipt` but leaves the corresponding `PromiseYieldTimeout` queue entry intact until its `expires_at` height is reached.
3. Because `yield_timeout_length_in_blocks` is a fixed protocol parameter, many yields created near the same time will expire at the same or nearby block heights, so the resolved-but-not-yet-cleaned timeout entries pile up and are drained all at once when that height is reached.

At drain time, each entry costs only a small trie read + a trie delete and consumes no `total.compute`, so the number of entries processable in a single chunk before `check_proof_size_limit_exceed()` trips is bounded by proof-witness size, not by the protocol's gas/compute accounting. This is exactly the shape of the reported Solidity issue: a batch-processing entry point (`process_receipts` → `resolve_promise_yield_timeouts`, the near-analog of `Voter::finalize()`) delegates to an internal drain routine (`resolve_promise_yield_timeouts`'s inner loop, the analog of `_processPendingRemovals()`) that lacks its own resource accounting for the "cheap removal" path, so a user-inflated backlog can be processed essentially for free inside one apply-chunk call.

### Impact Explanation
If the number of "free" entries processable before hitting the proof-size ceiling is large enough, an attacker can inflate chunk-apply wall-clock time for a single block without paying commensurate gas, degrading chunk-producer/validator performance and potentially causing missed block/chunk production (a soft chain-stall / resource-exhaustion effect) — this falls under "node panic or unbounded resource use, chain stall" from the acceptance criteria. It does not directly move funds or corrupt balances, but it is a legitimate underpriced-execution / unbounded-resource-use analog reachable purely from ordinary transactions (`yield_create` + `promise_yield_resume`), with no validator or network-layer involvement required.

### Likelihood Explanation
Reaching this path only requires calling standard, unprivileged host functions (`promise_yield_create`, `promise_yield_resume`) from a deployed contract — fully reachable from a submitted transaction. The attacker must pay gas to create and resume each yield, so the cost isn't zero, but that cost is bounded by the *creation-time* gas price rather than by the cost of *cleanup*, and creation can be spread over many blocks/many accounts to build up a large backlog cheaply relative to the eventual synchronized cleanup cost. I could not fully determine the exact default `proof_size_limit` value or measure how many timeout entries would be needed to produce a materially significant (multi-second) delay, so the magnitude of the practical impact is uncertain without further empirical measurement/benchmarking of the trie proof-size limit and per-entry trie-touch cost.

### Recommendation
Charge compute/gas within `resolve_promise_yield_timeouts` for every queue entry examined and removed — including the "already resolved, no resume receipt needed" branch — via `total.add(...)`, so the existing `total.compute >= compute_limit` check actually bounds this loop the same way it bounds the other receipt-processing loops. Alternatively/additionally, enforce an explicit maximum number of timeout entries processed per chunk (an explicit "batch size", as recommended in the analog report) independent of the proof-size check.

### Proof of Concept
Not executed; based on static code review of `resolve_promise_yield_timeouts` in `runtime/runtime/src/lib.rs` and the existing test scaffolding in `test-loop-tests/src/tests/yield_timeouts.rs` (e.g. `test_yield_timeout_under_congestion`, `create_congestion`) which demonstrates the harness needed to create many yields and drive them to their timeout height; a full PoC would extend that harness to (a) create N yields, (b) resume all of them immediately, and (c) measure apply-chunk time/proof size when their shared `expires_at` height is reached, comparing against the compute/gas actually billed for that block. [4](#0-3)

### Citations

**File:** runtime/runtime/src/lib.rs (L2946-2949)
```rust
    while promise_yield_indices.first_index < promise_yield_indices.next_available_index {
        if total.compute >= compute_limit || state_update.trie.check_proof_size_limit_exceed() {
            break;
        }
```

**File:** runtime/runtime/src/lib.rs (L2980-3018)
```rust
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
```

**File:** runtime/runtime/src/lib.rs (L3019-3025)
```rust
        }

        processed_yield_timeouts.push(queue_entry);
        state_update.remove(queue_entry_key);
        // Math checked above: first_index is less than next_available_index
        promise_yield_indices.first_index += 1;
    }
```

**File:** test-loop-tests/src/tests/yield_timeouts.rs (L310-332)
```rust
/// Note that these transactions start to be processed in the *second* block produced after they are
/// inserted to client 0's mempool.
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
