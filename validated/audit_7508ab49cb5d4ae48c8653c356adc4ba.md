### Title
`skip_stateful_validations` Ignores `max_nonce_for_validation_skip` Config, Hardcoding Signature-Bypass Threshold — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidatorConfig` declares a `max_nonce_for_validation_skip` field that is supposed to govern the maximum invoke-transaction nonce for which the gateway may skip the `__validate__` entry-point (account signature check). The free function `skip_stateful_validations` never receives or reads that field; it hardcodes `Nonce(Felt::ONE)` directly. The config field is therefore dead in the gateway path, and the signature-bypass threshold is permanently fixed at nonce 1 regardless of operator configuration.

### Finding Description

`StatefulTransactionValidatorConfig` defines and serialises `max_nonce_for_validation_skip`: [1](#0-0) 

The default value is `Nonce(Felt::ONE)`.

`run_pre_validation_checks` calls the free function `skip_stateful_validations`, passing only the transaction, the account nonce, and the mempool client — **not** `self.config`: [2](#0-1) 

Inside `skip_stateful_validations`, the threshold is hardcoded: [3](#0-2) 

When the function returns `true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags`, so `StatefulValidator::perform_validations` returns without ever calling `__validate__`: [4](#0-3) [5](#0-4) 

The config field is serialised and exposed in deployment configs but has zero effect on the gateway's admission decision.

### Impact Explanation

Any invoke transaction with `nonce == 1` submitted for an account that has a `deploy_account` in the mempool (or a recent block) is admitted to the mempool **without running the account's `__validate__` entry point**. Because `skip_stateful_validations` is a free function that never reads `self.config.max_nonce_for_validation_skip`, an operator who sets that field to `Nonce(Felt::ZERO)` to disable the bypass entirely has no effect. The gateway will continue to admit nonce-1 invoke transactions without signature verification. This satisfies the **High** impact criterion: *Mempool/gateway/RPC admission accepts invalid transactions before sequencing* — specifically, transactions whose signatures have not been verified are unconditionally admitted when the nonce-1 / account-nonce-0 condition is met.

### Likelihood Explanation

The trigger is fully unprivileged. Any external user can:
1. Submit a `deploy_account` for any address (no existing account required).
2. Immediately submit an `invoke` with `nonce = 1` for that same address.

The gateway will skip `__validate__` for the invoke and admit it to the mempool. The condition is reachable on every production gateway instance because the default config value (`Nonce(Felt::ONE)`) matches the hardcoded value, so the discrepancy is invisible in default deployments but becomes exploitable the moment an operator attempts to tighten the policy.

### Recommendation

Convert `skip_stateful_validations` from a free function into a method on `StatefulTransactionValidator` (or pass `max_nonce_for_validation_skip` as an explicit parameter) and replace the hardcoded `Nonce(Felt::ONE)` with the config value:

```rust
// In skip_stateful_validations (or its replacement method):
if tx.nonce() <= self.config.max_nonce_for_validation_skip
    && account_nonce == Nonce(Felt::ZERO)
{
    // existing mempool check …
}
```

This makes the threshold actually configurable and allows operators to set `max_nonce_for_validation_skip = Nonce(Felt::ZERO)` to disable the bypass entirely.

### Proof of Concept

1. Operator sets `max_nonce_for_validation_skip = Nonce(Felt::ZERO)` in gateway config, intending to require `__validate__` for all transactions.
2. Attacker submits `deploy_account` for address `A` (no signature from `A` required).
3. Attacker submits `invoke` with `sender_address = A`, `nonce = 1`, arbitrary (invalid) signature.
4. Gateway calls `run_pre_validation_checks` → `skip_stateful_validations`.
5. `skip_stateful_validations` checks `tx.nonce() == Nonce(Felt::ONE)` (hardcoded) and `account_nonce == Nonce(Felt::ZERO)` — both true.
6. `account_tx_in_pool_or_recent_block(A)` returns `true` (the deploy_account is in the pool).
7. Function returns `true`; `run_validate_entry_point` sets `validate: false`; `__validate__` is never called.
8. The invoke with the invalid signature is admitted to the mempool, contradicting the operator's explicit configuration. [6](#0-5) [7](#0-6)

### Citations

**File:** crates/apollo_gateway_config/src/config.rs (L283-299)
```rust
    pub max_nonce_for_validation_skip: Nonce,
    pub versioned_constants_overrides: Option<VersionedConstantsOverrides>,
    // Minimum gas price as percentage of threshold to accept transactions.
    pub min_gas_price_percentage: u8, // E.g., 80 to require 80% of threshold.
}

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-95)
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
        }
```
