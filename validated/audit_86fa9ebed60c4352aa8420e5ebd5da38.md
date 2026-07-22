### Title
Gateway `skip_stateful_validations` Admits Unsigned Invoke Transactions for Any Account With a Pending Deploy — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` UX feature in the gateway stateful validator skips the `__validate__` entry-point check for an invoke transaction when the account has a pending transaction in the mempool and the tx nonce is 1 with account nonce 0. The guard only checks whether *any* transaction exists for the sender address in the mempool — it does not verify that the submitter of the new invoke transaction is the legitimate account owner. An unprivileged attacker who knows a victim's account address can inject an unsigned (signature-invalid) invoke transaction into the mempool for that account, bypassing the gateway's signature check entirely.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` returns `true` (skip `__validate__`) when three conditions hold:

1. The transaction is an `Invoke` with `nonce == 1`
2. The on-chain account nonce is `0` (account not yet deployed)
3. `mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address())` returns `true` [1](#0-0) 

Condition 3 is satisfied whenever the victim's account address appears in the mempool — for example, because the victim legitimately submitted a `deploy_account` transaction. The check does not verify that the caller submitting the new invoke transaction is the same party who owns the account. [2](#0-1) 

When `skip_validate` is `true`, `run_validate_entry_point` sets `execution_flags.validate = false` and calls `blockifier_validator.validate(account_tx)`, which returns `Ok(())` immediately after `perform_pre_validation_stage` without ever calling the account's `__validate__` entry point. [3](#0-2) 

The `StatefulValidator::perform_validations` path confirms: when `execution_flags.validate` is `false`, the function returns after pre-validation without running `__validate__`. [4](#0-3) 

The `max_nonce_for_validation_skip` config defaults to `Nonce(Felt::ONE)`, so the window is exactly nonce=1. [5](#0-4) 

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An attacker who observes that victim account `A` has a `deploy_account` transaction in the mempool (nonce=0, account_nonce=0) can submit an `Invoke` transaction with `sender_address=A`, `nonce=1`, and arbitrary (attacker-controlled) calldata and an invalid/empty signature. The gateway skips `__validate__` and admits the transaction into the mempool. The transaction will fail at block-building time when the blockifier runs `__validate__` with the real signature check, but by then it occupies the nonce=1 slot for account `A`. If the attacker submits before the victim's legitimate nonce=1 invoke, the victim's transaction may be rejected as a duplicate nonce, breaking the intended deploy-account + invoke UX flow.

The invariant broken: **only the legitimate account owner (who can produce a valid signature) should be able to submit transactions for that account**. The gateway's `skip_stateful_validations` check verifies only that *some* transaction for the address exists in the mempool, not that the submitter controls the account.

### Likelihood Explanation

The attack requires only:
1. Knowledge of the victim's account address (public information on-chain/mempool)
2. Observing that the victim has a pending `deploy_account` in the mempool (observable via mempool P2P propagation)
3. Submitting an `Invoke` with `nonce=1` and any signature before the victim's own nonce=1 invoke

No privileged access, no special resources, and no cryptographic capability is required. The attack window is the time between the victim's `deploy_account` entering the mempool and the victim's own nonce=1 invoke being submitted.

### Recommendation

In `skip_stateful_validations`, additionally verify that the incoming invoke transaction's signature is consistent with the account's expected public key, or restrict the skip to cases where the invoke transaction was submitted together with (or immediately after) a `deploy_account` transaction from the same submitter. At minimum, the mempool should enforce that only one transaction per nonce per account is admitted, so that the attacker cannot displace the victim's legitimate nonce=1 transaction.

### Proof of Concept

1. Victim submits `deploy_account` tx for address `A` (nonce=0). It enters the mempool.
2. Attacker calls `POST /add_transaction` with:
   ```json
   {
     "type": "INVOKE",
     "version": "0x3",
     "sender_address": "<A>",
     "nonce": "0x1",
     "signature": [],
     "calldata": ["<malicious_calldata>"],
     ...
   }
   ```
3. Gateway stateful validator: `account_nonce=0`, `tx_nonce=1`, `account_tx_in_pool_or_recent_block(A)=true` → `skip_validate=true`.
4. `run_validate_entry_point` sets `execution_flags.validate=false`; `__validate__` is never called.
5. Transaction is admitted to the mempool with `nonce=1` for account `A`.
6. Victim's legitimate nonce=1 invoke is rejected by the mempool as a duplicate nonce for account `A`.
7. Victim's deploy-account + invoke UX flow is broken; victim must resubmit with a higher nonce. [6](#0-5) [7](#0-6)

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-94)
```rust
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
```

**File:** crates/apollo_gateway_config/src/config.rs (L289-299)
```rust
impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
            min_gas_price_percentage: 100,
            versioned_constants_overrides: None,
        }
    }
```
