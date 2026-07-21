### Title
Gateway `skip_stateful_validations` admits invoke transactions with arbitrary signatures when `account_tx_in_pool_or_recent_block` returns true — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` UX feature, intended to let a user submit a `deploy_account` + `invoke` pair atomically, uses `account_tx_in_pool_or_recent_block` as a proxy for "a deploy_account exists for this sender." That proxy is too broad: it returns `true` for any account that has *any* transaction in the pool or was seen in a recent committed block. When the condition fires, `run_validate_entry_point` is called with `validate: false`, causing `StatefulValidator::perform_validations` to return after `perform_pre_validation_stage` without ever calling `__validate__`. An attacker who observes a victim's `deploy_account` in the mempool can therefore submit a nonce-1 invoke from the victim's address with a completely arbitrary signature, and the gateway will admit it to the mempool without any signature check.

### Finding Description

**Trigger path** in `extract_state_nonce_and_run_validations`:

1. `get_nonce_from_state` returns `Nonce(0)` for the undeployed account.
2. `run_pre_validation_checks` calls `validate_state_preconditions` (nonce/resource-bounds), then `validate_by_mempool` (duplicate-hash + fee-escalation only — no signature check), then `skip_stateful_validations`. [1](#0-0) 

3. Inside `skip_stateful_validations`, the condition `tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO)` is satisfied. The function then calls `account_tx_in_pool_or_recent_block(sender_address)`. [2](#0-1) 

4. `account_tx_in_pool_or_recent_block` returns `true` if the address appears in `tx_pool` (any transaction type) **or** in `MempoolState::committed`/`staged` (any recently committed block). [3](#0-2) [4](#0-3) 

5. `skip_stateful_validations` returns `true`. Back in `run_validate_entry_point`, `validate: !skip_validate` is set to `false`. [5](#0-4) 

6. `StatefulValidator::perform_validations` for an Invoke transaction calls `perform_pre_validation_stage` (nonce increment, fee bounds, balance, proof-facts) and then hits the early-return guard: [6](#0-5) 

`__validate__` is never called. The signature is never verified.

**Why the proxy is wrong.** The code comment claims the check is sufficient because the account "either has a deploy_account transaction or transactions with future nonces that passed validations." But `account_tx_in_pool_or_recent_block` returns `true` for *any* transaction type in the pool, including a prior nonce-1 invoke that was itself admitted via the same skip. An attacker who observes a victim's `deploy_account` in the pool satisfies the condition without owning the account's private key. [3](#0-2) 

**Fee-escalation amplification.** If the victim already submitted a legitimate nonce-1 invoke alongside their `deploy_account`, the attacker can replace it via fee escalation (`validate_fee_escalation` only checks the fee ratio, not the signature): [7](#0-6) 

The attacker sets a higher fee (bounded by the victim's pre-funded balance, which `verify_can_pay_committed_bounds` confirms exists) and the victim's legitimate invoke is evicted from the pool.

### Impact Explanation

**Admission impact (High).** The gateway accepts an invoke transaction whose signature has never been verified and forwards it to the mempool. This directly satisfies: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

**Execution consequence.** When the batcher later executes the transaction it uses `new_for_sequencing` (`validate: true, strict_nonce_check: true`), so `__validate__` is called and the transaction fails. However:

- The victim's legitimate nonce-1 invoke may have been evicted by fee escalation, permanently disrupting the deploy_account + invoke flow.
- Depending on protocol version, a failed-validate transaction may still consume block space and charge fees to the victim's pre-funded account.

<cite repo="Ellentat/sequencer--012" path="crates/blockifier/src/transaction/account_transaction.rs" start="147"

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-355)
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
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L399-410)
```rust
    async fn run_pre_validation_checks(
        &self,
        executable_tx: &ExecutableTransaction,
        account_nonce: Nonce,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<bool> {
        self.validate_state_preconditions(executable_tx, account_nonce).await?;
        validate_by_mempool(executable_tx, account_nonce, mempool_client.clone()).await?;
        let skip_validate =
            skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
        Ok(skip_validate)
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

**File:** crates/apollo_mempool/src/mempool.rs (L115-117)
```rust
    fn contains_account(&self, address: ContractAddress) -> bool {
        self.staged.contains_key(&address) || self.committed.contains_key(&address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L757-791)
```rust
    /// `(address, nonce)` via fee escalation, without mutating any state. Returns the existing
    /// transaction to be replaced when a valid replacement exists, `None` when there is nothing to
    /// replace, or an error when a replacement is present but not permitted.
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
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```
