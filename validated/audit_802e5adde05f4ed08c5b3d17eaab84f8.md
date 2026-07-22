Let me trace through the exact code path carefully.

The code path is fully traceable. Here is the complete step-by-step execution trace and verdict.

---

### Title
Rejected Transaction Re-Sequenced via FIFO Rewind: `collect_txs_to_rewind` Includes Rejected Staged Txs, `remove_rejected_txs` Skips Their Removal — (`crates/apollo_mempool/src/fifo_transaction_queue.rs`)

### Summary

In Echonet/FIFO mode, when `commit_block` is called with `committed_nonces[A] = N+1` and `staged_txs` contains both `tx_R` (nonce N+1, not rejected) and `tx_X` (nonce N+2, rejected), `collect_txs_to_rewind` correctly marks address A for rewind (because `tx_R` is not rejected) but then blindly includes **all** staged txs for A with `nonce >= committed_nonce` in the rewind set — including the rejected `tx_X`. `rewind_txs` pushes `tx_X` back to the queue front and adds its hash to `rewound_tx_hashes`. `remove_rejected_txs` then skips `tx_X`'s removal because `rewound_tx_hashes.contains(tx_X.hash)`. The rejected transaction is left in both the pool and the queue and is returned by the next `get_txs` call.

### Finding Description

**Execution trace:**

**Step 1 — Address selection in `collect_txs_to_rewind` (lines 116–125):**

With `committed_nonces[A] = N+1`, the code looks for the staged tx at nonce N+1:

```
txs.iter().find(|tx| tx.tx_reference.nonce == nonce)  →  Some(tx_R)
is_none_or(|following_tx| !rejected_tx_hashes.contains(tx_R.hash))
  = is_none_or(!false)
  = true
```

Address A is marked for rewind. [1](#0-0) 

**Step 2 — Tx collection (lines 147–159):**

The filter keeps every staged tx for A where `nonce >= committed_nonce (N+1)`:

- `tx_R` (nonce N+1): N+1 ≥ N+1 → **included**
- `tx_X` (nonce N+2): N+2 ≥ N+1 → **included** ← rejected tx enters rewind set

There is no predicate here that excludes rejected transactions. [2](#0-1) 

**Step 3 — `rewind_txs` (lines 342–355):**

Both `tx_R.hash` and `tx_X.hash` are pushed to the queue front and collected into `rewound_hashes`. [3](#0-2) 

**Step 4 — `remove_rejected_txs` (lines 559–564):**

```rust
for tx_hash in rejected_tx_hashes {
    if rewound_tx_hashes.contains(&tx_hash) {
        continue;   // ← tx_X.hash is here; removal is skipped
    }
    ...
}
```

`tx_X.hash` is in both `rejected_tx_hashes` and `rewound_tx_hashes`, so the `continue` fires and `tx_X` is never removed from pool or queue. [4](#0-3) 

**Step 5 — `commit_block` pool cleanup (line 664):**

`remove_up_to_nonce_when_committed(A, N+1)` removes only txs with `nonce < N+1`. `tx_X` at nonce N+2 is untouched. [5](#0-4) 

**Result:** `tx_X` (rejected) sits at the front of the FIFO queue and in the pool. The next `get_txs` call returns it as a sequenceable transaction.

### Impact Explanation

A rejected transaction — one that failed execution and was explicitly passed in `rejected_tx_hashes` — is re-admitted to the sequencing queue and returned by `get_txs`. This directly violates the mempool's admission invariant. The sequencer will attempt to include and execute `tx_X` again in the next block, despite it having been marked as rejected. This maps to: **High — Mempool/gateway admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

The scenario requires no attacker privileges. It arises in normal Echonet operation whenever:
1. A block commits some txs for address A (setting `committed_nonces[A] = N+1`).
2. At least one staged tx for A at nonce N+1 is not rejected (`tx_R`).
3. At least one staged tx for A at a higher nonce is rejected (`tx_X`).

This is a routine multi-tx-per-account scenario in FIFO replay mode. Any user who submits a valid tx followed by an invalid tx (e.g., one that will fail execution) can trigger this path without any special access.

### Recommendation

In `collect_txs_to_rewind` Step 3, exclude rejected transactions from the returned rewind set:

```rust
self.staged_txs
    .iter()
    .filter(|tx| {
        let tx_ref = &tx.tx_reference;
        if !addresses_to_rewind.contains(&tx_ref.address) {
            return false;
        }
        if rejected_tx_hashes.contains(&tx_ref.tx_hash) {
            return false;  // ← add this guard
        }
        committed_nonces
            .get(&tx_ref.address)
            .is_none_or(|&committed_nonce| tx_ref.nonce >= committed_nonce)
    })
    .copied()
    .collect()
```

This ensures that `rewound_tx_hashes` never contains a rejected tx hash, so `remove_rejected_txs` will always remove them. [2](#0-1) 

### Proof of Concept

Concrete state to reproduce in a Rust unit test (FIFO mode):

```
committed_nonces = { A: N+1 }
staged_txs       = [ tx_R(address=A, nonce=N+1), tx_X(address=A, nonce=N+2) ]
rejected_tx_hashes = { tx_X.hash }
```

Call `rewind_txs(RewindData::Fifo { committed_nonces, rejected_tx_hashes })`.

**Assert:**
- `rewound_hashes` returned by `rewind_txs` contains `tx_X.hash` ← confirms the bug
- After calling `remove_rejected_txs(rejected_tx_hashes, &rewound_hashes)`, `tx_X` is still in the queue
- The next `get_txs` call returns `tx_X`

The `continue` branch at line 562 is the exact site where the invariant breaks: a tx that is simultaneously in `rejected_tx_hashes` and `rewound_tx_hashes` is silently kept alive. [6](#0-5)

### Citations

**File:** crates/apollo_mempool/src/fifo_transaction_queue.rs (L121-125)
```rust
                    txs.iter().find(|tx| tx.tx_reference.nonce == nonce).is_none_or(
                        |following_tx| {
                            !rejected_tx_hashes.contains(&following_tx.tx_reference.tx_hash)
                        },
                    )
```

**File:** crates/apollo_mempool/src/fifo_transaction_queue.rs (L147-159)
```rust
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

**File:** crates/apollo_mempool/src/fifo_transaction_queue.rs (L342-355)
```rust
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
```

**File:** crates/apollo_mempool/src/mempool.rs (L559-576)
```rust
        for tx_hash in rejected_tx_hashes {
            // In FIFO mode, if a rejected transaction was rewound, skip removal (keep in pool and
            // queue). Otherwise, remove it from both pool and queue.
            if rewound_tx_hashes.contains(&tx_hash) {
                continue;
            }

            if let Ok(tx) = self.tx_pool.remove(tx_hash) {
                self.tx_queue.remove_by_address(tx.contract_address());
                rejected_txs_counter += 1;
                self.decrement_stuck_txs_if_gap_account(tx.contract_address(), 1);
                account_nonce_updates
                    .entry(tx.contract_address())
                    .and_modify(|nonce| *nonce = (*nonce).min(tx.nonce()))
                    .or_insert(tx.nonce());
            } else {
                continue; // Transaction hash unknown to mempool, from a different node.
            }
```

**File:** crates/apollo_mempool/src/mempool.rs (L664-664)
```rust
            let n_removed_txs = self.tx_pool.remove_up_to_nonce_when_committed(address, next_nonce);
```
