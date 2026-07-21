### Title
Attacker Bypasses `__validate__` Signature Check for Invoke Transactions by Exploiting Pending Deploy-Account in Mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry-point call (i.e., signature verification) for any invoke transaction whose `sender_address` has a pending entry in the mempool and whose on-chain nonce is zero. Because the mempool check is not restricted to the same submitter, an attacker can craft an invoke transaction targeting any victim address that has a pending `deploy_account` transaction, attach an arbitrary or empty signature, and have it admitted to the mempool without signature verification.

---

### Finding Description

The `skip_stateful_validations` function decides whether to skip the blockifier's `__validate__` call:

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            ...
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
``` [1](#0-0) 

The condition is:
1. Transaction type is `Invoke`
2. Transaction nonce is `1`
3. On-chain account nonce is `0` (account not yet deployed)
4. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`

The `account_tx_in_pool_or_recent_block` check is:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

This returns `true` for **any** address that has any transaction in the pool — it does not verify that the deploy_account was submitted by the same entity as the invoke. When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [3](#0-2) 

Inside `StatefulValidator::perform_validations`, when `validate = false`, the function returns immediately after `perform_pre_validation_stage`, skipping the `__validate__` call entirely:

```rust
ApiTransaction::Invoke(_) => {
    ...
    tx.perform_pre_validation_stage(self.state(), &tx_context)?;
    if !tx.execution_flags.validate {
        return Ok(());
    }
    // `__validate__` call.
    let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
``` [4](#0-3) 

The `perform_pre_validation_stage` only checks nonce, fee bounds, and proof facts — it does **not** verify the transaction signature:

```rust
pub fn perform_pre_validation_stage<S: State + StateReader>(
    &self,
    state: &mut S,
    tx_context: &TransactionContext,
) -> TransactionPreValidationResult<()> {
    let tx_info = &tx_context.tx_info;
    Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;
    if self.execution_flags.charge_fee {
        self.check_fee_bounds(tx_context)?;
        verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
    }
    self.validate_proof_facts(&tx_context.block_context, state)?;
    Ok(())
}
``` [5](#0-4) 

The `skip_validate` flag is not stored in `InternalRpcTransaction` and does not propagate to the batcher. The batcher will call `__validate__` during execution, causing Eve's transaction to revert. However, the transaction was already admitted to the mempool with an invalid signature.

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An attacker can submit an invoke transaction for any victim address that has a pending `deploy_account` in the mempool, with an arbitrary or empty signature. The gateway admits this transaction without verifying the signature. The transaction will eventually revert during batcher execution (because the batcher does call `__validate__`), but:

- The invalid transaction occupies mempool capacity, potentially displacing legitimate transactions.
- The attacker can spam the mempool with unsigned invokes targeting any address with a pending deploy_account, causing denial-of-service.
- If the victim's account contract has a permissive `__validate__` (e.g., always returns success), the attacker's transaction executes successfully with the victim's nonce, permanently blocking the victim's own nonce-1 transaction.

---

### Likelihood Explanation

**Medium.** The attack requires a victim to have a pending `deploy_account` transaction in the mempool (a common UX pattern). The attacker only needs to observe the mempool (public information) and submit a crafted invoke. No privileged access is required.

---

### Recommendation

Replace the mempool presence check with a cryptographic binding between the deploy_account and the invoke. Specifically, require that the invoke transaction's `tx_hash` or a field within it commits to the deploy_account's `tx_hash`, or restrict the skip to cases where the gateway itself received the deploy_account from the same connection/session. A minimal fix is to check that the mempool contains a `deploy_account` transaction (not just any transaction) for the address:

```rust
// Instead of:
mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address())
// Use a new API:
mempool_client.deploy_account_tx_in_pool_or_recent_block(tx.sender_address())
```

This mirrors the STON.fi recommendation: propagate the initiator identity through the pipeline rather than trusting an attacker-controlled field.

---

### Proof of Concept

1. Alice submits `deploy_account` for address `V` (nonce=0). It enters the mempool. On-chain nonce for `V` is `0`.
2. Eve observes the mempool and sees `V` has a pending entry.
3. Eve submits `Invoke { sender_address: V, nonce: 1, signature: [0x0, 0x0], calldata: [<arbitrary>] }`.
4. Gateway stateful validation:
   - `validate_nonce`: `0 <= 1 <= max_allowed_nonce_gap` → passes.
   - `validate_by_mempool`: no duplicate → passes.
   - `skip_stateful_validations`: `nonce==1 && account_nonce==0 && account_tx_in_pool_or_recent_block(V)==true` → returns `true`.
   - `run_validate_entry_point(skip_validate=true)`: `__validate__` is skipped → returns `Ok(())`.
5. Eve's invoke is admitted to the mempool with an invalid signature.
6. The batcher later executes Eve's invoke; `__validate__` is called and fails (invalid signature), causing a revert. But the nonce slot for `V` at nonce=1 has been consumed in the mempool, blocking Alice's legitimate nonce-1 transaction. [1](#0-0) [6](#0-5) [2](#0-1)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-356)
```rust
    #[sequencer_latency_histogram(GATEWAY_VALIDATE_TX_LATENCY, true)]
    async fn run_validate_entry_point(
        &mut self,
        executable_tx: &ExecutableTransaction,
        skip_validate: bool,
    ) -> StatefulTransactionValidatorResult<()> {
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };

        // Build block context.
        let mut versioned_constants = VersionedConstants::get_versioned_constants(
            self.config.versioned_constants_overrides.clone(),
        );
        // The validation of a transaction is not affected by the casm hash migration.
        versioned_constants.disable_casm_hash_migration();

        let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        block_info.block_number = block_info.block_number.unchecked_next();
        let block_context = BlockContext::new(
            block_info,
            self.chain_info.clone(),
            versioned_constants,
            BouncerConfig::max(),
        );

        // Move state into the blocking task and run CPU-heavy validation.
        let state_reader_and_contract_manager = self.take_state_reader_and_contract_manager();

        let cur_span = Span::current();
        #[allow(clippy::result_large_err)]
        tokio::task::spawn_blocking(move || {
            cur_span.in_scope(|| {
                let state = CachedState::new(state_reader_and_contract_manager);
                let mut blockifier_validator = StatefulValidator::create(state, block_context);
                blockifier_validator.validate(account_tx)
            })
        })
        .await
        .map_err(|e| StarknetError {
            code: StarknetErrorCode::UnknownErrorCode(
                "StarknetErrorCode.InternalError".to_string(),
            ),
            message: format!("Blocking task join error when running the validate entry point: {e}"),
        })?
        .map_err(|e| StarknetError {
            code: StarknetErrorCode::KnownErrorCode(KnownStarknetErrorCode::ValidateFailure),
            message: e.to_string(),
        })?;
        Ok(())
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-461)
```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        // check if the transaction nonce is 1, meaning it is post deploy_account, and the
        // account nonce is zero, meaning the account was not deployed yet.
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            let account_address = tx.sender_address();
            debug!("Checking if deploy_account transaction exists for account {account_address}.");
            // We verify that a deploy_account transaction exists for this account. It is sufficient
            // to check if the account exists in the mempool since it means that either it has a
            // deploy_account transaction or transactions with future nonces that passed
            // validations.
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                .map_err(|err| mempool_client_err_to_deprecated_gw_err(&tx.signature(), err))
                .inspect(|exists| {
                    if *exists {
                        debug!("Found deploy_account transaction for account {account_address}.");
                    } else {
                        debug!(
                            "No deploy_account transaction found for account {account_address}."
                        );
                    }
                });
        }
    }

    Ok(false)
}
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-84)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L355-372)
```rust
    pub fn perform_pre_validation_stage<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let tx_info = &tx_context.tx_info;
        Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;

        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
        }

        self.validate_proof_facts(&tx_context.block_context, state)?;

        Ok(())
    }
```
