### Title
Gateway Admits Invoke Transaction with Invalid Signature via `skip_stateful_validations` Bypass — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function uses `account_tx_in_pool_or_recent_block` as a proxy for "a deploy-account transaction exists for this account." That check is broader than intended: it returns `true` for any account that has **any** transaction in the pool or recent block, not specifically a deploy-account. An attacker who observes a victim's deploy-account transaction entering the mempool can immediately submit a nonce-1 invoke with an **invalid signature** for the same address. The gateway skips `__validate__` for that invoke, admits it to the mempool, and the victim's legitimate nonce-1 invoke is then blocked by a duplicate-nonce conflict. When the batcher executes the attacker's transaction, `__validate__` is called normally, the transaction reverts, and the victim's pre-funded account is charged fees.

### Finding Description

`skip_stateful_validations` (lines 429–461) triggers when:
1. The transaction is an `Invoke`,
2. `tx.nonce() == Nonce(Felt::ONE)`,
3. `account_nonce == Nonce(Felt::ZERO)`, and
4. `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true`. [1](#0-0) 

When all four conditions hold, `run_pre_validation_checks` returns `skip_validate = true`. [2](#0-1) 

`run_validate_entry_point` then sets `execution_flags.validate = !skip_validate = false` and calls `blockifier_validator.validate(account_tx)`. [3](#0-2) 

Inside `StatefulValidator::perform_validations`, when `execution_flags.validate == false`, the function returns `Ok(())` immediately after `perform_pre_validation_stage` without ever calling the `__validate__` entry point: [4](#0-3) 

`perform_pre_validation_stage` still runs nonce, fee-bound, and balance checks, but **signature verification is entirely absent**. [5](#0-4) 

The code comment acknowledges the broader-than-intended check:

> "It is sufficient to check if the account exists in the mempool since it means that **either it has a deploy_account transaction or transactions with future nonces that passed validations**." [6](#0-5) 

The second case ("future nonces that passed validations") means the skip fires for any account with a pending transaction, not only for the deploy-account + invoke UX scenario.

### Impact Explanation

**Broken invariant**: Every invoke transaction admitted to the mempool must have passed `__validate__` (signature verification) at the gateway, unless the account is provably undeployed and a deploy-account is in-flight.

**Corrupted value**: `execution_flags.validate` is set to `false` for a transaction whose signature has never been checked, causing the gateway to return `Ok(())` and forward the transaction to the mempool.

**Consequence**:
- The attacker's invalid-signature nonce-1 invoke occupies the victim's nonce-1 slot in the mempool.
- The victim's legitimate nonce-1 invoke is rejected with `DuplicateNonce` (or must pay a higher fee to replace it).
- The batcher executes the attacker's transaction with `validate = true`; `__validate__` fails; the transaction reverts; the victim's pre-funded account is charged fees for the failed validation phase.

This matches: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

The preconditions are realistic and observable:
1. The victim pre-funds the to-be-deployed address (standard pattern).
2. The victim submits a deploy-account transaction (visible in the mempool).
3. The attacker submits a nonce-1 invoke with arbitrary calldata and a zeroed/random signature before the victim submits their own nonce-1 invoke.
4. The gateway admits it because `account_tx_

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-314)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
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
