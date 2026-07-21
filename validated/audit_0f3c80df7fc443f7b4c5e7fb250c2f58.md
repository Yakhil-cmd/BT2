I have all the code I need. Let me trace through the exact scenario step by step.

### Title
Rejected FIFO Transaction at Nonce N+1 Re-Admitted to Sequencing Queue When Co-Staged Nonce N Is Not Rejected — (`crates/apollo_mempool/src/fifo_transaction_queue.rs`, `crates/apollo_mempool/src/mempool.rs`)

---

### Summary

In FIFO (Echonet) mode, when two transactions from the same address are staged together — nonce=0 (valid) and nonce=1 (rejected) — and `commit_block` is called with neither committed, `collect_txs_to_rewind` marks the address for rewind because the *first* staged tx (nonce=0) is not rejected. This causes **both** nonce=0 and nonce=1 to be pushed back to the front of the FIFO queue. `remove_rejected_txs` then skips removal of nonce=1 because it appears in `rewound_tx_hashes`. The rejected transaction is permanently re-admitted to the sequencing queue without re-validation.

---

### Finding Description

The bug lives in the interaction between three functions across two files.

**`collect_txs_to_rewind` — address-level rewind decision (no-committed-nonce branch):** [1](#0-0) 

When `committed_nonces` has no entry for an address, the rewind decision is made solely on the *minimum-nonce* staged tx. If that tx is not rejected, the entire address is marked for rewind — including any higher-nonce staged txs that *are* rejected.

**Step 3 of `collect_txs_to_rewind` — all staged txs for rewound addresses are collected:** [2](#0-1) 

There is no filter here to exclude rejected tx hashes. Every staged tx for a rewound address is returned, including the rejected nonce=1 tx.

**`rewind_txs` — all collected txs pushed to queue front:** [3](#0-2) 

Both nonce=0 and nonce=1 are pushed to the front of the queue. `rewound_hashes` therefore contains both tx hashes.

**`remove_rejected_txs` — skips removal of any rejected tx that appears in `rewound_tx_hashes`:** [4](#0-3) 

Because nonce=1's hash is in `rewound_tx_hashes`, the `continue` fires and the rejected tx is never removed from the pool or queue.

**`commit_block` — the call chain that ties it together:** [5](#0-4) 

---

### Exact Execution Trace

```
State before commit_block:
  staged_txs = [tx_A(addr=0x1, nonce=0), tx_B(addr=0x1, nonce=1)]
  address_to_nonce = {}          // neither tx committed
  rejected_tx_hashes = {tx_B}

collect_txs_to_rewind({}, {tx_B}):
  staged_by_address = {0x1: [tx_A, tx_B]}
  no committed nonce for 0x1 → else branch
    first_tx = tx_A (min nonce=0)
    tx_A not in rejected_tx_hashes → address 0x1 IS rewound
  Step 3: both tx_A and tx_B pass filter → txs_to_rewind = [tx_A, tx_B]

rewind_txs:
  queue.push_front(tx_B), queue.push_front(tx_A)
  rewound_hashes = {tx_A.hash, tx_B.hash}

remove_rejected_txs({tx_B.hash}, {tx_A.hash, tx_B.hash}):
  tx_B.hash in rewound_tx_hashes → continue   ← BUG: rejected tx skipped
  tx_B remains in pool AND queue
```

After `commit_block`, the next `get_txs` call returns tx_A (nonce=0) and then tx_B (nonce=1). tx_B was rejected in the previous block and is re-sequenced without any re-validation.

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid/rejected transactions before sequencing.**

A transaction explicitly marked as rejected by the block executor is silently re-inserted at the front of the FIFO sequencing queue. On the next proposal round it will be returned by `get_txs` and submitted to the blockifier again. If the rejection was due to a transient condition this creates an infinite re-sequencing loop; if the rejection was due to a persistent invalidity (e.g., failed account validation, bad resource bounds) the sequencer wastes execution resources on a known-bad transaction every block cycle with no mechanism to evict it.

---

### Likelihood Explanation

Requires only that two transactions from the same address are staged in the same proposal round, the higher-nonce one is rejected, and neither is committed. This is a normal operating condition in Echonet/FIFO mode when a block partially fails. No privileged access is required — any user can submit two transactions from the same account.

---

### Recommendation

In `collect_txs_to_rewind`, Step 3 should filter out rejected tx hashes before returning the rewind set:

```rust
// Step 3 (corrected): exclude rejected txs from the rewind set
self.staged_txs
    .iter()
    .filter(|tx| {
        let tx_ref = &tx.tx_reference;
        if !addresses_to_rewind.contains(&tx_ref.address) {
            return false;
        }
        if rejected_tx_hashes.contains(&tx_ref.tx_hash) {
            return false;   // ← add this guard
        }
        committed_nonces
            .get(&tx_ref.address)
            .is_none_or(|&committed_nonce| tx_ref.nonce >= committed_nonce)
    })
    .copied()
    .collect()
```

This ensures that even when an address is marked for rewind, individual rejected transactions within that address's staged set are not pushed back into the queue and are correctly removed by `remove_rejected_txs`.

---

### Proof of Concept

Minimal Rust unit test (FIFO mode):

```rust
// 1. Add tx_A (addr=0x1, nonce=0) and tx_B (addr=0x1, nonce=1) to mempool.
// 2. Call get_txs(2) → both are staged; queue is empty.
// 3. Call commit_block with:
//      address_to_nonce = {}
//      rejected_tx_hashes = {tx_B.tx_hash}
// 4. Call get_txs(2) again.
// Assert: tx_B is NOT returned (it was rejected).
// Actual: tx_B IS returned — the rejected transaction is re-sequenced.
```

The test mirrors the proof idea in the question exactly. The assertion at step 4 will fail against the current production code, confirming the bug.

### Citations

**File:** crates/apollo_mempool/src/fifo_transaction_queue.rs (L126-136)
```rust
                } else {
                    // Address has no committed txs in this block.
                    // Use first nonce to decide if the address should be rewound:
                    // - first nonce rejected -> do not rewind address
                    // - first nonce not rejected -> rewind address
                    let first_tx = txs
                        .iter()
                        .min_by_key(|tx| tx.tx_reference.nonce)
                        .expect("staged_by_address entry must have at least one transaction");
                    !rejected_tx_hashes.contains(&first_tx.tx_reference.tx_hash)
                }
```

**File:** crates/apollo_mempool/src/fifo_transaction_queue.rs (L145-159)
```rust
        // Step 3: staged txs to rewind: keep addresses marked for rewind, excluding txs already
        // committed in this block (nonce < committed nonce)
        self.staged_txs
            .iter()
            .filter(|tx| {
                let tx_ref = &tx.tx_reference;
                if !addresses_to_rewind.contains(&tx_ref.address) {
                    return false;
                }
                committed_nonces
                    .get(&tx_ref.address)
                    .is_none_or(|&committed_nonce| tx_ref.nonce >= committed_nonce)
            })
            .copied()
            .collect()
```

**File:** crates/apollo_mempool/src/fifo_transaction_queue.rs (L341-359)
```rust
        let txs_to_rewind = self.collect_txs_to_rewind(committed_nonces, rejected_tx_hashes);
        let rewound_hashes: IndexSet<TransactionHash> = txs_to_rewind
            .into_iter()
            // We push each rewound tx to the FRONT, so iterate in reverse to preserve original
            // FIFO order among rewound transactions.
            .rev()
            .map(|tx| {
                debug!(
                    "FIFO rewind: tx_hash={}, timestamp={}, block_number={}, queue_before={:?}",
                    tx.tx_reference.tx_hash, tx.timestamp, tx.block_number, self.queue
                );
                InsertionSide::Front.push(&mut self.queue, tx);
                tx.tx_reference.tx_hash
            })
            .collect();

        self.staged_txs.clear();

        rewound_hashes
```

**File:** crates/apollo_mempool/src/mempool.rs (L559-564)
```rust
        for tx_hash in rejected_tx_hashes {
            // In FIFO mode, if a rejected transaction was rewound, skip removal (keep in pool and
            // queue). Otherwise, remove it from both pool and queue.
            if rewound_tx_hashes.contains(&tx_hash) {
                continue;
            }
```

**File:** crates/apollo_mempool/src/mempool.rs (L680-688)
```rust
        let addresses_to_rewind = self.state.commit(address_to_nonce.clone());

        let rewound_tx_hashes =
            self.rewind_txs(addresses_to_rewind, &address_to_nonce, &rejected_tx_hashes);
        debug!("Aligned mempool to committed nonces.");

        // Remove rejected transactions from the mempool.
        let mut account_nonce_updates =
            self.remove_rejected_txs(rejected_tx_hashes, &rewound_tx_hashes);
```
