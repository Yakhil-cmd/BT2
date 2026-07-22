### Title
Signature-Skipped Invoke Admission via `skip_stateful_validations` Race Window — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's UX shortcut that allows a nonce-1 invoke to bypass `__validate__` when a `deploy_account` is pending in the mempool contains no cryptographic check on the invoke's signature. Any unprivileged observer can inject an invoke transaction carrying an arbitrary (invalid) signature for a victim account during the deploy-account admission window. The transaction is admitted to the mempool without signature verification, and when the batcher later executes it the `__validate__` entry point fails, the transaction reverts, the victim's nonce is incremented, and fees are charged from the victim's pre-funded balance.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` returns `true` (skip) when three conditions hold simultaneously:

1. The incoming transaction is an `Invoke` with `tx.nonce() == 1`.
2. The on-chain account nonce is `0` (account not yet deployed).
3. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [1](#0-0) 

When `skip_validate = true`, `run_validate_entry_point` constructs `ExecutionFlags { validate: false, … }` and passes the transaction to the blockifier's `StatefulValidator::validate`, which then returns immediately without calling the account's `__validate__` entry point. [2](#0-1) 

The stateless validator never performs cryptographic signature verification — it only checks signature *length*. [3](#0-2) 

Condition 3 is satisfied by the *victim's* `deploy_account` transaction, not the attacker's. The check does not require the caller to be the account owner, nor does it verify that the invoke's signature is well-formed. [4](#0-3) 

The `InternalRpcTransaction` stored in the mempool carries no execution flags. When the batcher later retrieves and executes the transaction it uses `validate: true` (the default), so `__validate__` is called, the invalid signature is detected, the transaction reverts — but the nonce has already been incremented and fees have been charged. [5](#0-4) 

### Impact Explanation

An attacker can inject an invoke transaction with a completely invalid signature for any account that has a pending `deploy_account` in the mempool. The transaction is admitted (High: "Mempool/gateway/RPC admission accepts invalid transactions before sequencing"). Upon execution the victim's nonce is bumped to 2, their pre-funded balance is partially drained by the fee charge, and their own legitimate nonce-1 invoke is rendered stale and must be resubmitted with nonce 2.

### Likelihood Explanation

The attack window is the time between a `deploy_account` entering the mempool and being committed to a block. During this window, any observer of the mempool (including P2P peers) can submit the malicious invoke. No privileged access is required; the only cost to the attacker is the gas for the RPC call. New account deployments are a common, observable event.

### Recommendation

**Short term:** Before returning `skip_validate = true`, perform a lightweight ECDSA pre-check on the invoke's signature against the public key embedded in the pending `deploy_account`'s constructor calldata (or the class's known key slot). Alternatively, require that the invoke and deploy_account arrive in the same atomic batch from the same connection, rather than accepting them independently.

**Long term:** Decouple the UX shortcut from the signature-skip entirely. The gateway can admit the nonce-1 invoke into the mempool (for ordering purposes) while still running `__validate__` against a simulated post-deployment state, so that an invalid signature is caught at admission time rather than at execution time.

### Proof of Concept

1. Alice submits `deploy_account` for address `X` (valid signature, nonce 0). The transaction enters the mempool; `account_tx_in_pool_or_recent_block(X)` now returns `true`.

2. Bob (attacker) submits `invoke` from address `X`, nonce = 1, signature = `[0x0, 0x0]` (invalid).

3. Gateway stateless validation passes (signature length ≤ max). [3](#0-2) 

4. `extract_state_nonce_and_run_validations` reads account nonce = 0, calls `run_pre_validation_checks`. [6](#0-5) 

5. `skip_stateful_validations` evaluates: `tx.nonce()==1` ✓, `account_nonce==0` ✓, `account_tx_in_pool_or_recent_block(X)` = `true` ✓ → returns `true`. [7](#0-6) 

6. `run_validate_entry_point` is called with `validate: false`; the blockifier's `StatefulValidator` returns `Ok(())` without calling `__validate__`. [8](#0-7) 

7. Bob's invalid invoke is stored in the mempool alongside Alice's `deploy_account`.

8. Batcher executes the block: Alice's `deploy_account` succeeds (nonce → 1). Bob's invoke is executed with `validate: true`; `__validate__` is called, the ECDSA check fails, the transaction reverts. Alice's nonce is now 2; her balance is reduced by the fee; her own nonce-1 invoke is now stale.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L158-179)
```rust
    async fn extract_state_nonce_and_run_validations(
        &mut self,
        executable_tx: &ExecutableTransaction,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<Nonce> {
        let account_nonce =
            self.get_nonce_from_state(executable_tx.contract_address()).await.map_err(|e| {
                // TODO(noamsp): Fix this. Need to map the errors better.
                StarknetError::internal_with_signature_logging(
                    format!(
                        "Failed to get nonce for sender address {}",
                        executable_tx.contract_address()
                    ),
                    &executable_tx.signature(),
                    e,
                )
            })?;
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
    }
```

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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L180-195)
```rust
    fn validate_tx_signature_size(
        &self,
        tx: &RpcTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        let signature = tx.signature();

        let signature_length = signature.0.len();
        if signature_length > self.config.max_signature_length {
            return Err(StatelessTransactionValidatorError::SignatureTooLong {
                signature_length,
                max_signature_length: self.config.max_signature_length,
            });
        }

        Ok(())
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L74-95)
```rust
        match tx.tx {
            ApiTransaction::DeployAccount(_) | ApiTransaction::Declare(_) => self.execute(tx),
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;

                // Post validations.
                PostValidationReport::verify(
                    &tx_context,
                    &actual_cost,
                    tx.execution_flags.charge_fee,
                )?;

                Ok(())
            }
        }
```
