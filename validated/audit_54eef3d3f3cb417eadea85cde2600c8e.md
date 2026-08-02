No vulnerability found for this question.

**Reasoning:**

This is not an admission-boundary issue. `CrossShardCommitReceiver::start` and `CrossShardStateView::set_value` are internal, execution-time coordination primitives used only within the sharded block executor's parallel-round execution — they are not reachable from unprivileged transaction input, mempool, authenticator, or vm-validator paths at all.

Additionally, the premise of the exploit ("two shards writing to the same `StateKey` in different rounds" causing a stale overwrite in the same view) does not match the actual code: a fresh `CrossShardStateView` is constructed for every round via `CrossShardStateView::create_cross_shard_state_view`, called anew each time `execute_transactions_with_dependencies` runs for a sub-block/round [1](#0-0) . There is no shared, long-lived state view spanning multiple rounds into which "stale" writes from an earlier round could be delivered and overwrite a later authoritative write — each round's `CrossShardCommitReceiver::start` loop only processes messages targeted at that specific round, backed by that round's own `CrossShardStateView` instance [2](#0-1) . The `CrossShardCommitSender` explicitly routes each write to the specific `(dependent_shard_id, round_id)` pair recorded from static cross-shard dependency analysis of the block partitioning, not to an attacker-controllable target [3](#0-2) .

Even setting aside the round-scoping, `set_value` only writes into a `RemoteStateValue` slot that was pre-registered as a required cross-shard dependency for that round (`CrossShardStateView::new` pre-populates `cross_shard_data` from statically computed `required_edges_iter()`), so there is no mechanism for an unprivileged attacker to inject an out-of-order or extra write for an arbitrary key [4](#0-3) . This entire subsystem is validator-internal parallel execution infrastructure operating on already-ordered, already-partitioned block data, not a transaction admission path (mempool/vm-validator/authenticator), so it falls outside the required scope of this review (unauthorized sender/signer/fee-payer binding, replay, sequence/chain-id/expiry, or authenticator/multisig approval confusion at admission time).

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L103-118)
```rust
    pub fn execute_transactions_with_dependencies(
        shard_id: Option<ShardId>, // None means execution on global shard
        executor_thread_pool: Arc<rayon::ThreadPool>,
        transactions: Vec<TransactionWithDependencies<AnalyzedTransaction>>,
        cross_shard_client: Arc<dyn CrossShardClient>,
        cross_shard_commit_sender: Option<CrossShardCommitSender>,
        round: usize,
        state_view: &S,
        config: BlockExecutorConfig,
    ) -> Result<Vec<TransactionOutput>, VMStatus> {
        let (callback, callback_receiver) = oneshot::channel();

        let cross_shard_state_view = Arc::new(CrossShardStateView::create_cross_shard_state_view(
            state_view,
            &transactions,
        ));
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L24-44)
```rust
impl CrossShardCommitReceiver {
    pub fn start<S: StateView + Sync + Send>(
        cross_shard_state_view: Arc<CrossShardStateView<S>>,
        cross_shard_client: Arc<dyn CrossShardClient>,
        round: RoundId,
    ) {
        loop {
            let msg = cross_shard_client.receive_cross_shard_msg(round);
            match msg {
                RemoteTxnWriteMsg(txn_commit_msg) => {
                    let (state_key, write_op) = txn_commit_msg.take();
                    cross_shard_state_view
                        .set_value(&state_key, write_op.and_then(|w| w.as_state_value()));
                },
                CrossShardMsg::StopMsg => {
                    trace!("Cross shard commit receiver stopped for round {}", round);
                    break;
                },
            }
        }
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L102-125)
```rust
    fn send_remote_update_for_success(&self, txn_idx: TxnIndex, txn_output: &TransactionOutput) {
        let edges = self.dependent_edges.get(&txn_idx).unwrap();

        for (state_key, write_op) in txn_output.write_set().expect_write_op_iter() {
            if let Some(dependent_shard_ids) = edges.get(state_key) {
                for (dependent_shard_id, round_id) in dependent_shard_ids.iter() {
                    trace!("Sending remote update for success for shard id {:?} and txn_idx: {:?}, state_key: {:?}, dependent shard id: {:?}", self.shard_id, txn_idx, state_key, dependent_shard_id);
                    let message = RemoteTxnWriteMsg(RemoteTxnWrite::new(
                        state_key.clone(),
                        Some(write_op.clone()),
                    ));
                    if *round_id == GLOBAL_ROUND_ID {
                        self.cross_shard_client.send_global_msg(message);
                    } else {
                        self.cross_shard_client.send_cross_shard_msg(
                            *dependent_shard_id,
                            *round_id,
                            message,
                        );
                    }
                }
            }
        }
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_state_view.rs (L26-56)
```rust
    pub fn new(cross_shard_keys: HashSet<StateKey>, base_view: &'a S) -> Self {
        let mut cross_shard_data = HashMap::new();
        trace!(
            "Initializing cross shard state view with {} keys",
            cross_shard_keys.len(),
        );
        for key in cross_shard_keys {
            cross_shard_data.insert(key, RemoteStateValue::waiting());
        }
        Self {
            cross_shard_data,
            base_view,
        }
    }

    #[cfg(test)]
    fn waiting_count(&self) -> usize {
        self.cross_shard_data
            .values()
            .filter(|v| !v.is_ready())
            .count()
    }

    pub fn set_value(&self, state_key: &StateKey, state_value: Option<StateValue>) {
        self.cross_shard_data
            .get(state_key)
            .unwrap()
            .set_value(state_value);
        // uncomment the following line to debug waiting count
        // trace!("waiting count for shard id {} is {}", self.shard_id, self.waiting_count());
    }
```
