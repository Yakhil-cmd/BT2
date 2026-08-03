No vulnerability found for this question.

**Rationale:** `TransactionSliceMetadata::Block { parent, child }` in [1](#0-0)  is internal block-executor bookkeeping. The `child` hash (returned by `append_state_checkpoint_to_block`) is only used to tag where the block epilogue/state-checkpoint transaction should be appended [2](#0-1)  and to build the `BlockEpilogue` transaction hash binding in mock/production executors [3](#0-2) . It is populated from the `ExecutableBlock`'s id, which is supplied by the consensus/execution layer (`execute_and_update_state`, `parent_block_id`) — not from attacker-controlled transaction batch contents [4](#0-3) .

Critically, per-transaction chain-id validation happens in the VM prologue against the on-chain `ChainId` resource during transaction validation/execution — it is entirely independent of `TransactionSliceMetadata::Block`'s `child` hash. Nothing in `by_transaction_execution_sharded` [5](#0-4)  uses `append_state_checkpoint_to_block` for anything other than tagging the state-checkpoint boundary; it plays no role in binding a transaction's chain-id, sender, signer, sequence number, or expiry. There is no code path by which unprivileged transaction batch content can influence or mismatch this block id, and no code path where this value affects chain-id/epoch binding checks for admitted transactions. This falls outside the admission boundary (mempool/vm-validator/authenticator) entirely, and the described exploit mechanism does not exist in the reviewed code.

### Citations

**File:** types/src/block_executor/transaction_slice_metadata.rs (L9-18)
```rust
pub enum TransactionSliceMetadata {
    /// Block execution. Specifies the parent (executed) block, and the child (to be executed)
    /// block.
    Block { parent: HashValue, child: HashValue },
    /// Chunk execution, e.g., state sync or replay. Specifies the start (inclusive) and the end
    /// (exclusive) versions of a transaction slice.
    Chunk { begin: Version, end: Version },
    /// The origin of transactions is not known, e.g., running a test.
    Unknown,
}
```

**File:** types/src/block_executor/transaction_slice_metadata.rs (L47-57)
```rust
    /// Returns the hash of the block where to append the state checkpoint (i.e., the current hash
    /// of [TransactionSliceMetadata::Block]). For other variants, returns [None].
    pub fn append_state_checkpoint_to_block(&self) -> Option<HashValue> {
        use TransactionSliceMetadata::*;

        match self {
            Unknown => None,
            Block { child, .. } => Some(*child),
            Chunk { .. } => None,
        }
    }
```

**File:** execution/executor/src/tests/mock_vm/mod.rs (L200-209)
```rust
        let mut block_epilogue_txn = None;
        if !skip_rest {
            if let Some(block_id) = transaction_slice_metadata.append_state_checkpoint_to_block() {
                block_epilogue_txn = Some(Transaction::block_epilogue_v0(
                    block_id,
                    BlockEndInfo::new_empty(),
                ));
                outputs.push(TransactionOutput::new_empty_success());
            }
        }
```

**File:** execution/executor/src/block_executor/mod.rs (L98-116)
```rust
    fn execute_and_update_state(
        &self,
        block: ExecutableBlock,
        parent_block_id: HashValue,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> ExecutorResult<()> {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "execute_and_state_checkpoint"]);

        self.maybe_initialize()?;
        // guarantee only one block being executed at a time
        let _guard = self.execution_lock.lock();
        self.inner
            .read()
            .as_ref()
            .ok_or_else(|| ExecutorError::InternalError {
                error: "BlockExecutor is not reset".into(),
            })?
            .execute_and_update_state(block, parent_block_id, onchain_config)
    }
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L193-236)
```rust
    pub fn by_transaction_execution_sharded<V: VMBlockExecutor>(
        transactions: PartitionedTransactions,
        auxiliary_infos: Vec<AuxiliaryInfo>,
        parent_state: &LedgerState,
        state_view: CachedStateView,
        onchain_config: BlockExecutorConfigFromOnchain,
        append_state_checkpoint_to_block: Option<HashValue>,
    ) -> Result<ExecutionOutput> {
        let state_view_arc = Arc::new(state_view);
        let mut transaction_outputs = Self::execute_block_sharded::<V>(
            transactions.clone(),
            state_view_arc.clone(),
            onchain_config,
        )?;
        if onchain_config.hotness_in_epilogue() {
            Self::convert_write_sets_to_v1(&mut transaction_outputs);
        }

        // TODO(Manu): Handle state checkpoint here.

        // TODO(skedia) add logic to emit counters per shard instead of doing it globally.

        // Unwrapping here is safe because the execution has finished and it is guaranteed that
        // the state view is not used anymore.
        let state_view = Arc::try_unwrap(state_view_arc).unwrap();
        Parser::parse()
            .first_version(state_view.next_version())
            .transactions(
                PartitionedTransactions::flatten(transactions)
                    .into_iter()
                    .map(|t| t.into_txn().into_inner())
                    .collect(),
            )
            .transaction_outputs(transaction_outputs)
            .auxiliary_infos(auxiliary_infos)
            .parent_state(parent_state)
            .base_state_view(state_view)
            .prime_state_cache(false)
            .is_block(append_state_checkpoint_to_block.is_some())
            .transaction_info_v1(onchain_config.transaction_info_v1())
            .hot_state_root_in_txn_info(onchain_config.hot_state_root_in_txn_info())
            .compute_trading_native_state_roots(onchain_config.compute_trading_native_state_roots())
            .build()
    }
```
