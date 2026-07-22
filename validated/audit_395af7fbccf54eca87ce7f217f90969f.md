### Title
Fee Escalation Replaces Staged (In-Flight) Transactions Without Staged-State Guard — (File: `crates/apollo_mempool/src/mempool.rs`)

### Summary

`validate_fee_escalation()` does not check whether the existing transaction at `(address, nonce)` is currently **staged** (already handed to the batcher via `get_txs()`). Because `get_txs()` performs a soft-delete — staged transactions remain in `tx_pool` — an incoming replacement with a sufficient fee bump can evict a staged, in-flight transaction from the pool. The mempool admits the replacement as valid and destroys the staged transaction's pool entry, breaking the invariant that a staged transaction is locked for the current block.

---

### Finding Description

**Step 1 — Soft-delete in `get_txs()`**

`get_txs()` pops transactions from `tx_queue` and calls `state.stage()` to increment the staged nonce, but it explicitly does **not** remove the transaction from `tx_pool`:

```rust
// Soft-delete: return without deleting from mempool.
.cloned()
.collect()
``` [1](#0-0) 

The staged transaction therefore remains findable by `tx_pool.get_by_address_and_nonce(address, nonce)`.

**Step 2 — `validate_fee_escalation()` has no staged-state guard**

`validate_fee_escalation()` checks only: (a) no delayed-declare front-run, (b) fee escalation enabled, (c) an existing transaction exists at the same `(address, nonce)` in the pool, and (d) the incoming transaction's tip and max-L2-gas-price exceed the threshold. It does **not** check whether the found transaction is staged:

```rust
let Some(existing_tx_reference) = self.tx_pool.get_by_address_and_nonce(address, nonce)
else {
    return Ok(None);
};

if !self.should_replace_tx(&existing_tx_reference, &incoming_tx_reference) {
    ...
    return Err(MempoolError::DuplicateNonce { address, nonce });
}

Ok(Some(existing_tx_reference))
``` [2](#0-1) 

**Step 3 — `remove_replaced_tx()` unconditionally removes the staged transaction**

When `add_tx_validations()` receives `Some(existing_tx_reference)` from `validate_fee_escalation()`, it calls `remove_replaced_tx()`, which removes the staged transaction from both `tx_queue` and `tx_pool` without any staged-state check:

```rust
fn remove_replaced_tx(&mut self, existing_tx_reference: TransactionReference) {
    self.tx_queue.remove_txs(&[existing_tx_reference]);
    self.tx_pool
        .remove(existing_tx_reference.tx_hash)
        .expect("Transaction hash from pool must exist.");
    ...
}
``` [3](#0-2) 

**Contrast with TTL protection**

The existing test `expired_staged_txs_are_not_deleted` confirms that staged transactions are explicitly protected from TTL-based removal. No analogous protection exists for fee-escalation replacement. [4](#0-3) 

---

### Impact Explanation

Two distinct outcomes arise depending on whether the current block proposal succeeds or fails:

**Case A — Block commits normally:**
The batcher executes the original staged tx_A and reports it in `commit_block`. The mempool's `commit_block` then removes all transactions up to the committed nonce, including the replacement tx_B. tx_B was admitted by the gateway and consumed mempool capacity, but is silently discarded without ever being executed. The gateway accepted an invalid transaction (a replacement for a staged tx).

**Case B — Block proposal fails (consensus timeout, validator disagreement, etc.):**
The batcher discards its in-progress block. On the next `get_txs()` call, tx_A is gone from `tx_pool` (removed by fee escalation). The mempool returns tx_B instead. tx_B — which may carry different calldata, a different target contract, or different resource bounds — is executed in the next block in place of tx_A. The user's original in-flight transaction is silently dropped and substituted.

This matches the allowed impact: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

---

### Likelihood Explanation

- Block proposal failures are a normal part of Tendermint-based BFT consensus (timeouts, network partitions, competing proposals).
- The trigger requires only that the account owner submit a replacement with a ≥10% fee bump (the default `fee_escalation_percentage`) while their transaction is staged.
- No privileged access is required; any account can trigger this against its own staged transaction.
- The window is the duration of a single block proposal, which is bounded by the consensus timeout.

---

### Recommendation

In `validate_fee_escalation()`, after finding an existing transaction at `(address, nonce)`, check whether that transaction's nonce is currently staged. If it is, reject the replacement:

```rust
fn validate_fee_escalation(
    &self,
    incoming_tx_reference: TransactionReference,
) -> MempoolResult<Option<TransactionReference>> {
    let TransactionReference { address, nonce, .. } = incoming_tx_reference;

    self.validate_no_delayed_declare_front_run(incoming_tx_reference)?;

    if !self.config.static_config.enable_fee_escalation {
        if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
            return Err(MempoolError::DuplicateNonce { address, nonce });
        }
        return Ok(None);
    }

    let Some(existing_tx_reference) = self.tx_pool.get_by_address_and_nonce(address, nonce)
    else {
        return Ok(None);
    };

    // NEW: Staged transactions are locked for the current block; reject replacement.
    if self.state.is_nonce_staged(address, nonce) {
        return Err(MempoolError::DuplicateNonce { address, nonce });
    }

    if !self.should_replace_tx(&existing_tx_reference, &incoming_tx_reference) {
        return Err(MempoolError::DuplicateNonce { address, nonce });
    }

    Ok(Some(existing_tx_reference))
}
```

A helper `MempoolState::is_nonce_staged(address, nonce)` can be implemented by checking whether `self.staged.get(&address)` equals `nonce + 1` (i.e., the staged nonce is the increment of the transaction's nonce, meaning that transaction was the one staged). [5](#0-4) 

---

### Proof of Concept

1. Account `0xA` submits **tx_A** (`nonce=5`, `tip=100`, `calldata=[transfer 10 STRK to Bob]`). tx_A enters `tx_pool` and `tx_queue`.
2. Batcher calls `get_txs(1)`. tx_A is popped from `tx_queue`, `state.stage()` sets `staged[0xA] = 6`. tx_A **remains in `tx_pool`**.
3. Account `0xA` submits **tx_B** (`nonce=5`, `tip=111`, `calldata=[transfer 10 STRK to Mallory]`). The gateway calls `mempool.validate_tx()` → `validate_fee_escalation()` finds tx_A in the pool via `get_by_address_and_nonce(0xA, 5)`, computes `111 >= 100 * 1.10 = 110` → replacement permitted.
4. Gateway calls `mempool.add_tx()` → `remove_replaced_tx()` removes tx_A from `tx_pool`. tx_B is inserted.
5. Consensus fails to reach agreement on the current block (e.g., timeout). The batcher discards the in-progress block.
6. Batcher calls `get_txs(1)` for the new block. tx_A is gone. tx_B is returned.
7. tx_B is executed: 10 STRK transferred to Mallory instead of Bob.

The mempool admitted tx_B (step 3–4) when it should have rejected it, because tx_A was already staged and locked for the current block. [6](#0-5) [7](#0-6)

### Citations

**File:** crates/apollo_mempool/src/mempool.rs (L119-130)
```rust
    fn stage(&mut self, tx_reference: &TransactionReference) -> MempoolResult<()> {
        let next_nonce = try_increment_nonce(tx_reference.nonce)?;
        if let Some(existing_nonce) = self.staged.insert(tx_reference.address, next_nonce) {
            assert_eq!(
                try_increment_nonce(existing_nonce)?,
                next_nonce,
                "Staged nonce should be an increment of an existing nonce."
            );
        }

        Ok(())
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L327-387)
```rust
    pub fn get_txs(&mut self, n_txs: usize) -> MempoolResult<Vec<InternalRpcTransaction>> {
        // All transactions are enqueued in FIFO mode.
        if !self.is_fifo() {
            self.add_ready_declares();
        }
        let mut eligible_tx_references: Vec<TransactionReference> = Vec::with_capacity(n_txs);
        let mut n_remaining_txs = n_txs;

        let mut account_nonce_updates = AddressToNonce::new();
        while n_remaining_txs > 0 && self.tx_queue.has_ready_txs() {
            let chunk = self.tx_queue.pop_ready_chunk(n_remaining_txs);

            let (valid_txs, expired_txs_updates) = self.prune_expired_nonqueued_txs(chunk);
            account_nonce_updates.extend(expired_txs_updates);

            // In FIFO mode, all transactions are already enqueued. In fee-priority mode,
            // we need to enqueue the next eligible transaction for each address.
            if !self.is_fifo() {
                self.enqueue_next_eligible_txs(&valid_txs)?;
            }

            n_remaining_txs -= valid_txs.len();
            eligible_tx_references.extend(valid_txs);
        }

        // Update the mempool state with the given transactions' nonces.
        for tx_reference in &eligible_tx_references {
            self.state.stage(tx_reference)?;
        }

        let n_returned_txs = eligible_tx_references.len();
        if n_returned_txs != 0 {
            info!("Returned {n_returned_txs} out of {n_txs} transactions, ready for sequencing.");
            debug!(
                "Returned mempool txs: {:?}",
                eligible_tx_references.iter().map(|tx| tx.tx_hash).collect::<Vec<_>>()
            );
            // Mark these txs as "taken for batching" (returned by `get_txs`). The
            // `TRANSACTION_TIME_SPENT_UNTIL_BATCHED` metric is recorded only once they actually
            // commit (to avoid counting txs that were returned by `get_txs` but ultimately not
            // included).
            let now = self.clock.now();
            for tx_ref in &eligible_tx_references {
                self.tx_pool.mark_taken_for_batching(tx_ref.tx_hash, now);
            }
        }

        metric_set_get_txs_size(n_returned_txs);
        self.update_accounts_with_gap(account_nonce_updates);
        self.update_state_metrics();

        Ok(eligible_tx_references
            .iter()
            .map(|tx_reference| {
                self.tx_pool
                    .get_by_tx_hash(tx_reference.tx_hash)
                    .expect("Transaction hash from queue must appear in pool.")
            })
            .cloned() // Soft-delete: return without deleting from mempool.
            .collect())
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L760-792)
```rust
    fn validate_fee_escalation(
        &self,
        incoming_tx_reference: TransactionReference,
    ) -> MempoolResult<Option<TransactionReference>> {
        let TransactionReference { address, nonce, .. } = incoming_tx_reference;

        self.validate_no_delayed_declare_front_run(incoming_tx_reference)?;

        if !self.config.static_config.enable_fee_escalation {
            if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
                return Err(MempoolError::DuplicateNonce { address, nonce });
            };

            return Ok(None);
        }

        let Some(existing_tx_reference) = self.tx_pool.get_by_address_and_nonce(address, nonce)
        else {
            // Replacement irrelevant: no existing transaction with the same nonce for address.
            return Ok(None);
        };

        if !self.should_replace_tx(&existing_tx_reference, &incoming_tx_reference) {
            info!(
                "{existing_tx_reference} was not replaced by {incoming_tx_reference} due to \
                 insufficient fee escalation."
            );
            // TODO(Elin): consider adding a more specific error type / message.
            return Err(MempoolError::DuplicateNonce { address, nonce });
        }

        Ok(Some(existing_tx_reference))
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L797-805)
```rust
    fn remove_replaced_tx(&mut self, existing_tx_reference: TransactionReference) {
        debug!("{existing_tx_reference} is being replaced via fee escalation.");

        self.tx_queue.remove_txs(&[existing_tx_reference]);
        self.tx_pool
            .remove(existing_tx_reference.tx_hash)
            .expect("Transaction hash from pool must exist.");
        self.decrement_stuck_txs_if_gap_account(existing_tx_reference.address, 1);
    }
```

**File:** crates/apollo_mempool/src/fee_mempool_test.rs (L1357-1388)
```rust
fn expired_staged_txs_are_not_deleted() {
    // Create a mempool with a fake clock.
    let fake_clock = Arc::new(FakeClock::default());
    let mut mempool = Mempool::new(
        MempoolConfig {
            dynamic_config: MempoolDynamicConfig { transaction_ttl: Duration::from_secs(60) },
            ..Default::default()
        },
        fake_clock.clone(),
    );

    // Add 2 transactions to the mempool, and stage one.
    let staged_tx =
        add_tx_input!(tx_hash: 1, address: "0x0", tx_nonce: 0, account_nonce: 0, tip: 100);
    let nonstaged_tx =
        add_tx_input!(tx_hash: 2, address: "0x0", tx_nonce: 1, account_nonce: 0, tip: 100);
    add_tx(&mut mempool, &staged_tx);
    add_tx(&mut mempool, &nonstaged_tx);
    assert_eq!(mempool.get_txs(1).unwrap(), vec![staged_tx.tx.clone()]);

    // Advance the clock beyond the TTL.
    fake_clock.advance(mempool.config.dynamic_config.transaction_ttl + Duration::from_secs(5));

    // Add another transaction to trigger the cleanup, and verify the staged tx is still in the
    // mempool. The non-staged tx should be removed.
    let another_tx =
        add_tx_input!(tx_hash: 3, address: "0x1", tx_nonce: 0, account_nonce: 0, tip: 100);
    add_tx(&mut mempool, &another_tx);
    let expected_mempool_content =
        MempoolTestContentBuilder::new().with_pool([staged_tx.tx, another_tx.tx]).build();
    expected_mempool_content.assert_eq(&mempool.content());
}
```
