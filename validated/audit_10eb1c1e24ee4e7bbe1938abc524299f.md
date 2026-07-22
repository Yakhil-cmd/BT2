Looking at the code carefully to trace the exact path described.

The vulnerability is real. Here is the precise analysis:

---

### Title
Stale Declare Inserted into `tx_pool` Without Nonce Guard After `commit_block` Advances Account Nonce — (`crates/apollo_mempool/src/mempool.rs`)

### Summary

`add_ready_declares` unconditionally calls `add_tx_inner` for every declare whose delay has elapsed, with no check against the committed account nonce. If `commit_block` advanced the account nonce while the declare was sitting in `delayed_declares`, the stale declare is inserted into `tx_pool` with a nonce strictly below the committed nonce, violating the pool invariant and consuming capacity.

### Finding Description

**Step 1 — Declare is queued in `delayed_declares`, not `tx_pool`.**

When a declare arrives in fee-priority mode, `add_tx` pushes it to `delayed_declares` and returns without touching `tx_pool`: [1](#0-0) 

**Step 2 — `commit_block` does not purge `delayed_declares`.**

`commit_block` calls `tx_pool.remove_up_to_nonce_when_committed` to evict stale pool entries and updates `self.state.committed` to the new nonce. It never iterates over or touches `delayed_declares`: [2](#0-1) 

So a declare at nonce 0 that is sitting in `delayed_declares` survives `commit_block` that advances the account to nonce 1.

**Step 3 — `add_ready_declares` has no nonce guard.**

Once the clock advances past `declare_delay`, `add_ready_declares` pops the entry and calls `add_tx_inner` directly — no nonce comparison, no call to `validate_incoming_tx`, no call to `state.validate_incoming_tx`: [3](#0-2) 

**Step 4 — `add_tx_inner` inserts into `tx_pool` unconditionally before any nonce check.**

The pool insert at line 598–600 happens before the nonce comparison at line 609. The nonce comparison only controls whether the tx is also enqueued; it does not gate the pool insert: [4](#0-3) 

After `commit_block`, `self.state.resolve_nonce` returns 1 (from `self.state.committed`). Since `tx_reference.nonce (0) != account_nonce (1)`, the stale declare is **not** added to the queue — but it **is** already in `tx_pool`.

**Step 5 — Pool invariant is violated.**

`TransactionPool::insert` performs no nonce-vs-committed-state check; it only guards against hash duplicates: [5](#0-4) 

The stale declare (nonce 0, committed nonce 1) now resides in `tx_pool`, counted toward `size_in_bytes` and `len`.

### Impact Explanation

- **Pool invariant violated:** A transaction with nonce strictly below the committed account nonce is resident in `tx_pool`. This is the exact invariant the pool is documented to maintain.
- **Capacity consumed:** The stale declare counts toward `capacity_in_bytes`. Under the right timing (many accounts each submitting a declare just before their nonce is committed), this can fill the pool with untouchable stale entries, causing valid incoming transactions to be rejected via `exceeds_capacity`.
- **Not sequenced:** Because the stale declare is not added to the queue (`tx_reference.nonce != account_nonce`), it will not be directly sequenced in fee-priority mode. The "potentially sequenced before cleanup" claim in the question is **not supported** by the code.
- **Cleanup:** The stale declare is eventually evicted by TTL (`remove_txs_older_than`), but until then it occupies pool capacity and corrupts pool state.

### Likelihood Explanation

Triggerable by any unprivileged user who submits a declare transaction and whose account nonce is then advanced by a committed block before `declare_delay` elapses. No special privileges required. The window is exactly the `declare_delay` duration.

### Recommendation

In `add_ready_declares`, before calling `add_tx_inner`, check the declare's nonce against the current committed/staged nonce via `state.validate_incoming_tx`. If the nonce is stale, drop the declare (and emit a metric/log) rather than inserting it into the pool. Alternatively, `commit_block` should scan `delayed_declares` and evict entries whose nonce is now below the committed nonce.

### Proof of Concept

```rust
// Pseudocode for a Rust unit test
let mut mempool = Mempool::new(config_with_declare_delay(Duration::from_secs(10)), fake_clock.clone());

// 1. Submit declare at nonce 0.
mempool.add_tx(AddTransactionArgs {
    tx: make_declare(account, nonce_0),
    account_state: AccountState { address: account, nonce: nonce_0 },
}).unwrap();
// Declare is in delayed_declares, NOT in tx_pool.
assert!(mempool.tx_pool.tx_pool().is_empty());

// 2. Commit a block that advances account to nonce 1.
mempool.commit_block(CommitBlockArgs {
    address_to_nonce: [(account, nonce_1)].into(),
    rejected_tx_hashes: Default::default(),
});
// delayed_declares still holds the nonce-0 declare.

// 3. Advance clock past declare_delay.
fake_clock.advance(Duration::from_secs(11));

// 4. Trigger add_ready_declares via get_txs.
let _ = mempool.get_txs(10);

// 5. Assert: stale declare (nonce 0) is now in tx_pool despite committed nonce being 1.
assert_eq!(mempool.tx_pool.tx_pool().len(), 1);
// The tx in the pool has nonce 0 < committed nonce 1 — invariant violated.
```

### Citations

**File:** crates/apollo_mempool/src/mempool.rs (L502-509)
```rust
        let should_delay_declare =
            matches!(&args.tx.tx, InternalRpcTransactionWithoutTxHash::Declare(_))
                && !self.is_fifo();
        if should_delay_declare {
            self.delayed_declares.push_back(self.clock.now(), args);
        } else {
            self.add_tx_inner(args);
        }
```

**File:** crates/apollo_mempool/src/mempool.rs (L598-616)
```rust
        self.tx_pool
            .insert(tx)
            .expect("Duplicate transactions should cause an error during the validation stage.");

        let AccountState { address, nonce: incoming_account_nonce } = account_state;
        let account_nonce = self.state.resolve_nonce(address, incoming_account_nonce);

        if self.is_fifo() {
            // FIFO mode: add all transactions to the queue immediately, regardless of nonce.
            // Keep all transactions from the same address in the queue.
            self.insert_to_tx_queue(tx_reference);
        } else if tx_reference.nonce == account_nonce {
            // Fee mode: only add transactions with matching account nonce.
            // Remove queued transactions the account might have. This includes old nonce
            // transactions that have become obsolete; those with an equal nonce should
            // already have been removed via fee escalation (`remove_replaced_tx`).
            self.tx_queue.remove_by_address(address);
            self.insert_to_tx_queue(tx_reference);
        }
```

**File:** crates/apollo_mempool/src/mempool.rs (L619-630)
```rust
    fn add_ready_declares(&mut self) {
        let now = self.clock.now();
        while let Some((submission_time, _args)) = self.delayed_declares.front() {
            if now - self.config.static_config.declare_delay < *submission_time {
                break;
            }
            let (_submission_time, args) =
                self.delayed_declares.pop_front().expect("Delay declare should exist.");
            self.add_tx_inner(args);
        }
        self.update_state_metrics();
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L663-666)
```rust
            // Remove from pool.
            let n_removed_txs = self.tx_pool.remove_up_to_nonce_when_committed(address, next_nonce);
            metric_count_committed_txs(n_removed_txs);
            self.decrement_stuck_txs_if_gap_account(address, n_removed_txs);
```

**File:** crates/apollo_mempool/src/transaction_pool.rs (L60-95)
```rust
    pub fn insert(&mut self, tx: InternalRpcTransaction) -> MempoolResult<()> {
        let tx_reference = TransactionReference::new(&tx);
        let tx_hash = tx_reference.tx_hash;
        let tx_size = tx.total_bytes();

        // Insert to pool.
        if let hash_map::Entry::Vacant(entry) = self.tx_pool.entry(tx_hash) {
            entry.insert(tx);
        } else {
            return Err(MempoolError::DuplicateTransaction { tx_hash });
        }

        // Insert to account mapping.
        let unexpected_existing_tx = self.txs_by_account.insert(tx_reference);
        if unexpected_existing_tx.is_some() {
            panic!(
                "Transaction pool consistency error: transaction with hash {tx_hash} does not
                appear in main mapping, but transaction with same nonce appears in the account
                mapping",
            )
        };

        // Insert to timed mapping.
        let unexpected_existing_tx = self.txs_by_submission_time.insert(tx_reference);
        if unexpected_existing_tx.is_some() {
            panic!(
                "Transaction pool consistency error: transaction with hash {tx_hash} does not
                appear in main mapping, but transaction with same hash appears in the timed
                mapping",
            )
        };

        self.size.add(tx_size);

        Ok(())
    }
```
