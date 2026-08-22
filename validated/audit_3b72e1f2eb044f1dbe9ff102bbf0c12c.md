### Title
Per-receipt storage-proof limit is enforced per FunctionCall action, not per receipt, allowing storage-proof amplification via batched actions - ([File: runtime/near-vm-runner/src/logic/recorded_storage_counter.rs])

### Summary
`RecordedStorageCounter` bounds the storage proof growth relative to a baseline captured at the time of its own construction, but a fresh counter (with a fresh baseline) is created for every `FunctionCall` action inside a receipt, rather than once per receipt. An attacker can therefore batch many `FunctionCall` actions in a single receipt, each individually staying just under `per_receipt_storage_proof_size_limit` (4MB), while the cumulative storage proof recorded for the whole receipt grows far beyond the documented 4MB hard cap.

### Finding Description
`RecordedStorageCounter::new` stores `initial_storage_size` at construction time and later computes the delta from `last_observed_storage_size` in `observe_size`/`get_storage_size`, comparing only that delta against `size_limit`: [1](#0-0) 

The counter is instantiated inside `VMLogic::new` (legacy path) and `Ctx::new` (wasmtime path), both seeding `initial_storage_size` from `ext.get_recorded_storage_size()`: [2](#0-1) [3](#0-2) 

`get_recorded_storage_size()` in `RuntimeExt` returns the trie's cumulative `recorded_storage_size_upper_bound()`, which is shared and monotonically increasing across the whole receipt (indeed the whole chunk), not reset per action: [4](#0-3) 

Critically, `apply_action_receipt` loops over all actions of a receipt and, for each `FunctionCall`, calls `action_function_call`, which constructs a brand-new `RuntimeExt`/`VMLogic`(`Ctx`) for every single action: [5](#0-4) [6](#0-5) 

Because a new `RecordedStorageCounter` is created per action, `initial_storage_size` is re-baselined to the *already elevated* cumulative trie-recorder value each time. This means the enforced limit is "at most 4MB of *additional* proof per action", not "at most 4MB of proof per receipt". Since `max_actions_per_receipt` allows up to 100 actions per receipt (per config snapshot), an attacker can chain many `FunctionCall` actions (e.g., via promise batch actions or a single transaction with multiple `FunctionCall` actions) each reading ~3.9MB of storage proof, and the receipt as a whole can generate storage proof far exceeding the 4MB hard cap documented in `docs/misc/state_witness_size_limits.md`, without ever triggering `HostError::RecordedStorageExceeded`.

The only other place the runtime measures recorded-storage growth per receipt is purely for metrics (`process_receipt_with_metrics`), which records histograms but performs no limit enforcement: [7](#0-6) 

The `main_storage_proof_size_soft_limit` is a chunk-wide *soft* limit checked after receipts execute (stops scheduling more receipts once exceeded), but it does not retroactively invalidate or bound an already-executing receipt's total proof size, so it does not close this gap for a single oversized receipt.

### Impact Explanation
This breaks the "hard limit" invariant documented for `per_receipt_storage_proof_size_limit` (4MB per receipt), which exists specifically to bound `ChunkStateWitness` size (target ~17MiB total). A single malicious receipt with many batched `FunctionCall` actions can generate storage proof many times larger than 4MB (bounded only by `max_actions_per_receipt` × ~4MB), causing an oversized `ChunkStateWitness` to be distributed to validators. This maps to the "storage/witness metering bypass leading to node resource exhaustion" bounty class — oversized witnesses increase validator CPU/memory/bandwidth costs and risk chunk validation failures or stalls, since validators must replay and validate proofs of this size.

### Likelihood Explanation
This is fully reachable by an unprivileged account: deploy a contract with a method that performs trie reads generating close to (but under) the per-action limit, then submit a transaction/receipt with multiple `FunctionCall` actions targeting that method (or use promise batch actions to combine several calls into one receipt). No special permissions, validator status, or protocol version gating prevents this; it only requires standard `SignedTransaction`/receipt construction through public RPC. It is fully repeatable and deterministic.

### Recommendation
Track the recorded storage proof baseline and limit at the receipt level rather than per Ctx/VMLogic instantiation. E.g., pass a persistent `RecordedStorageCounter` (or its `initial_storage_size` baseline) through `apply_action_receipt`/`RuntimeExt` construction so the same instance (with the same original baseline, established once at the start of the receipt) is reused/consulted across all `FunctionCall` actions within a receipt, ensuring the aggregate storage proof recorded across all actions in the receipt is checked against `per_receipt_storage_proof_size_limit`.

### Proof of Concept
Integration test plan (extending `integration-tests/src/tests/features/storage_proof_size_limit.rs`):
1. Deploy a contract with method `read_n_megabytes(from, to)` (already used in existing test) that reads storage keys producing ~1MB of proof per call.
2. Construct a single transaction/receipt containing N `FunctionCall` actions (e.g., N=5, each reading a distinct ~3.9MB-worth-under-limit chunk, or more realistically N calls each generating just under 4MB using disjoint keys) batched via `SignedTransaction::from_actions` with multiple `Action::FunctionCall` entries, or via promise batch actions targeting the same contract.
3. Execute the receipt and assert:
   - `FinalExecutionStatus::SuccessValue(_)` (no `RecordedStorageExceeded` error raised for any individual action), and
   - The cumulative `recorded_storage_size_upper_bound()` diff for the receipt (as tracked by `RECEIPT_RECORDED_SIZE_UPPER_BOUND` metric or directly via `trie.recorded_storage_size_upper_bound()` before/after `process_receipt_with_metrics`) exceeds `per_receipt_storage_proof_size_limit` (4,000,000 bytes).
4. Expected (buggy) result: receipt succeeds with total recorded storage proof > 4MB despite the per-receipt hard limit; no error is raised.

### Citations

**File:** runtime/near-vm-runner/src/logic/recorded_storage_counter.rs (L12-33)
```rust
impl RecordedStorageCounter {
    pub fn new(initial_storage_size: usize, size_limit: usize) -> Self {
        Self { initial_storage_size, last_observed_storage_size: initial_storage_size, size_limit }
    }

    /// Update the latest observed storage proof size and check if it exceeds the limit.
    /// Should be called after every trie operation.
    pub fn observe_size(&mut self, latest_storage_proof_size: usize) -> Result<(), VMLogicError> {
        self.last_observed_storage_size = latest_storage_proof_size;

        let current_size = self.get_storage_size()?;
        if current_size > self.size_limit {
            let limit_u64 = self.size_limit.try_into().map_err(|_| {
                VMLogicError::InconsistentStateError(InconsistentStateError::IntegerOverflow)
            })?;
            return Err(VMLogicError::HostError(HostError::RecordedStorageExceeded {
                limit: ByteSize::b(limit_u64),
            }));
        }

        Ok(())
    }
```

**File:** runtime/near-vm-runner/src/logic/logic.rs (L256-259)
```rust
        let recorded_storage_counter = RecordedStorageCounter::new(
            ext.get_recorded_storage_size(),
            config.limit_config.per_receipt_storage_proof_size_limit,
        );
```

**File:** runtime/near-vm-runner/src/wasmtime_runner/mod.rs (L345-350)
```rust
        let current_account_locked_balance = context.account_locked_balance;
        let config = Arc::clone(&result_state.config);
        let recorded_storage_counter = RecordedStorageCounter::new(
            ext.get_recorded_storage_size(),
            result_state.config.limit_config.per_receipt_storage_proof_size_limit,
        );
```

**File:** runtime/runtime/src/ext.rs (L310-317)
```rust
    fn get_recorded_storage_size(&self) -> usize {
        // `recorded_storage_size()` doesn't provide the exact size of storage proof
        // as it doesn't cover some corner cases (see https://github.com/near/nearcore/issues/10890),
        // so we use the `upper_bound` version to estimate how much storage proof
        // could've been generated by the receipt. As long as upper bound is
        // under the limit we can be sure that the actual value is also under the limit.
        self.trie_update.trie().recorded_storage_size_upper_bound()
    }
```

**File:** runtime/runtime/src/lib.rs (L833-854)
```rust
        // Executing actions one by one
        for (action_index, action) in action_receipt.actions().iter().enumerate() {
            let action_hash = create_action_hash_from_receipt_id(
                receipt.receipt_id(),
                apply_state.block_height,
                action_index,
            );
            let mut new_result = self.apply_action(
                action,
                state_update,
                apply_state,
                preparation_pipeline,
                &mut account,
                &mut actor_id,
                receipt,
                &action_receipt,
                Arc::clone(&promise_results),
                &action_hash,
                action_index,
                &action_receipt.actions(),
                epoch_info_provider,
            )?;
```

**File:** runtime/runtime/src/lib.rs (L2245-2278)
```rust
        let state_update = &mut processing_state.state_update;
        let trie = state_update.trie();
        let recorded_storage_size_before = trie.recorded_storage_size();
        let storage_proof_size_upper_bound_before = trie.recorded_storage_size_upper_bound();

        // Main logic
        let result = self.process_receipt(
            processing_state,
            receipt,
            &mut receipt_sink,
            &mut validator_proposals,
        );

        let shard_id_str = processing_state.apply_state.shard_id.to_string();
        let trie = processing_state.state_update.trie();

        let recorded_storage_diff = trie.recorded_storage_size() - recorded_storage_size_before;
        let recorded_storage_upper_bound_diff =
            trie.recorded_storage_size_upper_bound() - storage_proof_size_upper_bound_before;
        metrics::RECEIPT_RECORDED_SIZE
            .with_label_values(&[shard_id_str.as_str()])
            .observe(recorded_storage_diff as f64);
        metrics::RECEIPT_RECORDED_SIZE_UPPER_BOUND
            .with_label_values(&[shard_id_str.as_str()])
            .observe(recorded_storage_upper_bound_diff as f64);
        let recorded_storage_proof_ratio =
            recorded_storage_upper_bound_diff as f64 / f64::max(1.0, recorded_storage_diff as f64);
        // Record the ratio only for large receipts, small receipts can have a very high ratio,
        // but the ratio is not that important for them.
        if recorded_storage_upper_bound_diff > 100_000 {
            metrics::RECEIPT_RECORDED_SIZE_UPPER_BOUND_RATIO
                .with_label_values(&[shard_id_str.as_str()])
                .observe(recorded_storage_proof_ratio);
        }
```

**File:** runtime/runtime/src/function_call.rs (L60-73)
```rust
    let mut receipt_manager = ReceiptManager::default();
    let mut runtime_ext = RuntimeExt::new(
        state_update,
        &mut receipt_manager,
        account_id.clone(),
        account.clone(),
        *action_hash,
        apply_state.epoch_id,
        apply_state.block_height,
        epoch_info_provider,
        apply_state.current_protocol_version,
        config.wasm_config.storage_get_mode,
        Arc::clone(&apply_state.trie_access_tracker_state),
    );
```
