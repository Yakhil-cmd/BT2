No vulnerability found for this question.

**Reasoning:**

The premise that an unprivileged attacker can "craft" a `RejectedTransactionSummary` doesn't hold up — this struct is never constructed from external, attacker-controlled network/API input. It is built internally by `MempoolNotifier::notify_failed_txn` in consensus, strictly from the fields of the actual `SignedTransaction` that failed VM execution: `sender: txn.sender(), replay_protector: txn.replay_protector(), hash: txn.committed_hash(), reason: *reason` [1](#0-0) . These are derived deterministically from the transaction's own bytes/signature, so sender/replay_protector/hash always correspond to one another for the same transaction — there is no attacker-reachable code path that lets these three fields be set independently or bound to an unrelated transaction.

This `RejectNotification` is sent over an intra-node channel (`consensus_to_mempool_sender`) from the local consensus component to the local mempool component [2](#0-1) , dispatched only via `process_quorum_store_request` in `mempool/src/shared_mempool/tasks.rs` [3](#0-2) . It is not reachable from REST/BCS transaction submission, authenticator parsing, or any other unprivileged/API-facing entrypoint, so the boundary condition ("must start from unprivileged transaction, authenticator, API, or proof input") is not satisfied.

Even setting aside reachability, `TransactionStore::reject_transaction` itself defends against a sender/replay_protector mismatch: it only removes a transaction if `hash_index.get(hash)` returns an entry whose stored `(account, replay_protector)` matches the ones passed in [4](#0-3) . So even a hypothetical mismatched summary (same sender/replay_protector as a different pending txn, but with a hash belonging to the txn actually rejected) would fail this equality check and be a no-op, as confirmed by the existing test `test_reject_transaction`, which explicitly checks that "reject with wrong hash should have no effect" [5](#0-4) .

Since (1) the summary's fields are not independently attacker-controllable, (2) the call path is intra-node/privileged rather than unprivileged-input-driven, and (3) the store enforces hash-to-(sender, replay_protector) binding before eviction, no admission/replay/binding guarantee is broken.

### Citations

**File:** consensus/src/txn_notifier.rs (L62-71)
```rust
        let mut rejected_txns = vec![];
        for (txn, status) in user_txns.iter().zip_eq(user_txn_statuses) {
            if let TransactionStatus::Discard(reason) = status {
                rejected_txns.push(RejectedTransactionSummary {
                    sender: txn.sender(),
                    replay_protector: txn.replay_protector(),
                    hash: txn.committed_hash(),
                    reason: *reason,
                });
            }
```

**File:** consensus/src/txn_notifier.rs (L78-85)
```rust
        let (callback, callback_rcv) = oneshot::channel();
        let req = QuorumStoreRequest::RejectNotification(rejected_txns, callback);

        // send to shared mempool
        self.consensus_to_mempool_sender
            .clone()
            .try_send(req)
            .map_err(anyhow::Error::from)?;
```

**File:** mempool/src/shared_mempool/tasks.rs (L772-783)
```rust
        QuorumStoreRequest::RejectNotification(transactions, callback) => {
            counters::mempool_service_transactions(
                counters::COMMIT_CONSENSUS_LABEL,
                transactions.len(),
            );
            process_rejected_transactions(&smp.mempool, transactions);
            (
                QuorumStoreResponse::CommitResponse(),
                callback,
                counters::COMMIT_CONSENSUS_LABEL,
            )
        },
```

**File:** mempool/src/core_mempool/transaction_store.rs (L724-735)
```rust
    pub fn reject_transaction(
        &mut self,
        account: &AccountAddress,
        replay_protector: ReplayProtector,
        hash: &HashValue,
    ) {
        let mut txn_to_remove = None;
        if let Some((indexed_account, indexed_replay_protector)) = self.hash_index.get(hash) {
            if account == indexed_account && replay_protector == *indexed_replay_protector {
                txn_to_remove = self.get_mempool_txn(account, replay_protector).cloned();
            }
        }
```

**File:** mempool/src/tests/core_mempool_test.rs (L434-447)
```rust
    // reject with wrong hash should have no effect
    pool.reject_transaction(
        &TestTransaction::get_address(0),
        ReplayProtector::SequenceNumber(0),
        &txns[1].committed_hash(), // hash of other txn
        &DiscardedVMStatus::MALFORMED,
    );
    assert!(pool
        .get_transaction_store()
        .get(
            &TestTransaction::get_address(0),
            ReplayProtector::SequenceNumber(0)
        )
        .is_some());
```
