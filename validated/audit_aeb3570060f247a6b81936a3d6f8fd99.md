Based on my research, I found a concrete analog in nearcore's receipt/validator-account processing path.

### Title
Unhandled `RuntimeError` variants (`UnexpectedIntegerOverflow`, `ReceiptValidationError`, generic `StorageError`) cause the whole shard's chunk-apply loop to `panic!`, stalling the chain instead of failing gracefully - (File: `chain/chain/src/runtime/mod.rs`)

### Summary
The reported Voter bug is a class of "batch/loop processing that reverts (or here: crashes) entirely when a single item in the loop fails, instead of isolating the failure." nearcore's runtime explicitly acknowledges this same anti-pattern with a `TODO(#2152): process gracefully` comment, but still panics the whole node process when certain errors occur while iterating over validator accounts or receipts during chunk application.

### Finding Description
`Runtime::apply` iterates over several loops per chunk: reward distribution across all stake_info accounts in `update_validator_accounts`, and receipt-by-receipt processing for local/delayed/incoming receipts. Some per-item error paths are explicitly turned into a `panic!` at the boundary between `runtime/runtime` and `chain/chain`: [1](#0-0) 

Specifically, `RuntimeError::UnexpectedIntegerOverflow` and `RuntimeError::ReceiptValidationError` are converted to `panic!` rather than a recoverable `Error`. These errors are produced deep inside the per-item loops:
- `update_validator_accounts` (the per-epoch reward-distribution loop, directly analogous to `Voter.distribute` looping over gauges) returns `RuntimeError::UnexpectedIntegerOverflow` if any single account's `checked_add`/`checked_sub` fails: [2](#0-1) 
- The incoming-receipt processing loop calls `validate_receipt` per receipt and maps any failure straight to `RuntimeError::ReceiptValidationError`: [3](#0-2) 
- The delayed-receipt loop treats a receipt-validation failure as `StorageError::StorageInconsistentState`, which is also unconditionally panicked on for any non-`FlatStorageBlockNotSupported`/`MissingTrieValue` variant: [4](#0-3)  and [5](#0-4) 

Unlike the well-designed local/delayed/incoming receipt-execution path (which isolates per-receipt `ActionError`s and only delays receipts on gas/compute exhaustion — see the deliberate design in `docs/RuntimeSpec/Components/RuntimeCrate.md` and `process_local_receipts`/`process_delayed_receipts`), these specific error classes bypass that isolation and abort the entire shard's chunk apply for *all* nodes applying that chunk, not just a failing transaction sender. [6](#0-5) 

### Impact Explanation
If any single item in these loops (one validator account's reward accounting, or one receipt among many incoming/delayed receipts) hits one of these unhandled error variants, the panic crashes the node process applying the chunk for that shard. Because it's deterministic state transition logic, every honest node applying the same chunk hits the same panic, causing a chain stall for the shard (or the whole chain if it's a shared shard), matching the report's "protocol may be stopped" and gas-cost-loss impact, but at the more severe node-crash/chain-halt level explicitly called out as an acceptable impact category (node panic / chain stall).

### Likelihood Explanation
The `TODO(#2152): process gracefully` comment shows the nearcore team is already aware these paths are not properly handled — they represent a known-incomplete area rather than a hypothetical one. Reachability differs by variant: `UnexpectedIntegerOverflow` requires balances near `u128::MAX`, which is not practically reachable under current NEAR token-supply bounds, making that sub-case low likelihood. The receipt-validation panics are more concerning: they require a receipt that was considered valid when created (and thus queued/forwarded), but becomes invalid by the time it's processed on the receiving/delaying shard — e.g. due to differing runtime config between epochs (protocol version changes to `wasm_config.limit_config`) or cross-shard/cross-version validation-rule mismatches. This is a narrower but structurally real trigger surface, not purely theoretical.

### Recommendation
Replace the `panic!` branches for `RuntimeError::UnexpectedIntegerOverflow` and `RuntimeError::ReceiptValidationError` in `chain/chain/src/runtime/mod.rs` (and the corresponding `StorageInconsistentState` panic in `apply_chunk`) with graceful, isolated error handling equivalent to how `ActionError`s are already isolated per receipt — e.g., mark only the offending chunk/receipt as invalid (triggering the existing "invalid chunk" / challenge machinery) instead of aborting the whole node process. This mirrors the report's recommendation to avoid "process everything or fail everything" semantics in per-item loops.

### Proof of Concept
Not independently reproducible without a live devnet/testnet capable of forcing a receipt to pass creation-time validation but fail `validate_receipt` at processing time (e.g., by changing `wasm_config.limit_config` via a protocol upgrade boundary, or exploiting a cross-shard config mismatch), or by accumulating validator locked balance close to `u128::MAX`. The code paths that would panic given such input are cited above: [1](#0-0) [3](#0-2)

### Citations

**File:** chain/chain/src/runtime/mod.rs (L356-369)
```rust
            .map_err(|e| match e {
                RuntimeError::InvalidTxError(err) => {
                    tracing::warn!(?err, "invalid tx");
                    Error::InvalidTransactions
                }
                // TODO(#2152): process gracefully
                RuntimeError::UnexpectedIntegerOverflow(reason) => {
                    panic!("RuntimeError::UnexpectedIntegerOverflow {reason}")
                }
                RuntimeError::StorageError(e) => Error::StorageError(e),
                // TODO(#2152): process gracefully
                RuntimeError::ReceiptValidationError(e) => panic!("{}", e),
                RuntimeError::ValidatorError(e) => e.into(),
            })?;
```

**File:** chain/chain/src/runtime/mod.rs (L1264-1273)
```rust
        ) {
            Ok(result) => Ok(result),
            Err(e) => match e {
                Error::StorageError(err) => match &err {
                    StorageError::FlatStorageBlockNotSupported(_)
                    | StorageError::MissingTrieValue(..) => Err(err.into()),
                    _ => panic!("{err}"),
                },
                _ => Err(e),
            },
```

**File:** runtime/runtime/src/lib.rs (L1589-1636)
```rust
        for (account_id, max_of_stakes) in &validator_accounts_update.stake_info {
            if let Some(mut account) = get_account(state_update, account_id)? {
                if let Some(reward) = validator_accounts_update.validator_rewards.get(account_id) {
                    tracing::debug!(target: "runtime", %account_id, %reward, locked = %account.locked(), "account adding reward to stake");
                    account.set_locked(account.locked().checked_add(*reward).ok_or_else(|| {
                        RuntimeError::UnexpectedIntegerOverflow("update_validator_accounts".into())
                    })?);
                }

                tracing::debug!(target: "runtime",
                       %account_id, locked = %account.locked(), %max_of_stakes,
                       "account stake and max of stakes"
                );
                if account.locked() < *max_of_stakes {
                    return Err(StorageError::StorageInconsistentState(format!(
                        "FATAL: staking invariant does not hold. \
                         Account stake {} is less than maximum of stakes {} in the past three epochs",
                        account.locked(),
                        max_of_stakes)).into());
                }
                let last_proposal = *validator_accounts_update
                    .last_proposals
                    .get(account_id)
                    .unwrap_or(&Balance::ZERO);
                let return_stake = account
                    .locked()
                    .checked_sub(max(*max_of_stakes, last_proposal))
                    .ok_or_else(|| {
                        RuntimeError::UnexpectedIntegerOverflow(
                            "update_validator_accounts - return stake".into(),
                        )
                    })?;
                tracing::debug!(target: "runtime", %account_id, %return_stake, "account return stake");
                account.set_locked(account.locked().checked_sub(return_stake).ok_or_else(
                    || {
                        RuntimeError::UnexpectedIntegerOverflow(
                            "update_validator_accounts - set_locked".into(),
                        )
                    },
                )?);
                account.set_amount(account.amount().checked_add(return_stake).ok_or_else(
                    || {
                        RuntimeError::UnexpectedIntegerOverflow(
                            "update_validator_accounts - set_amount".into(),
                        )
                    },
                )?);

```

**File:** runtime/runtime/src/lib.rs (L2385-2411)
```rust
    fn process_delayed_receipts(
        &self,
        mut processing_state: &mut ApplyProcessingReceiptState,
        receipt_sink: &mut ReceiptSink,
        compute_limit: u64,
        validator_proposals: &mut Vec<ValidatorStake>,
    ) -> Result<(), RuntimeError> {
        let delayed_processing_start = std::time::Instant::now();
        let protocol_version = processing_state.protocol_version;
        let mut delayed_receipt_count = 0;

        let mut next_schedule_after = {
            let mut prep_lookahead_iter =
                processing_state.delayed_receipts.peek_iter(&processing_state.state_update);
            schedule_contract_preparation(
                &mut processing_state.pipeline_manager,
                &processing_state.state_update,
                &mut prep_lookahead_iter,
            )
        };

        loop {
            if processing_state.total.compute >= compute_limit
                || processing_state.state_update.trie.check_proof_size_limit_exceed()
            {
                break;
            }
```

**File:** runtime/runtime/src/lib.rs (L2443-2455)
```rust
            // Validating the delayed receipt. If it fails, it's likely the state is inconsistent.
            validate_receipt(
                &processing_state.apply_state.config.wasm_config.limit_config,
                &receipt,
                protocol_version,
                ValidateReceiptMode::ExistingReceipt,
            )
            .map_err(|e| {
                StorageError::StorageInconsistentState(format!(
                    "Delayed receipt {:?} in the state is invalid: {}",
                    receipt, e
                ))
            })?;
```

**File:** runtime/runtime/src/lib.rs (L2509-2518)
```rust
        for receipt in processing_state.incoming_receipts {
            // Validating new incoming no matter whether we have available gas or not. We don't
            // want to store invalid receipts in state as delayed.
            validate_receipt(
                &processing_state.apply_state.config.wasm_config.limit_config,
                receipt,
                protocol_version,
                ValidateReceiptMode::ExistingReceipt,
            )
            .map_err(RuntimeError::ReceiptValidationError)?;
```
