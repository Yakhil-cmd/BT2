### Title
`skip_stateful_validations` Hardcodes `Nonce(Felt::ONE)` and Ignores `max_nonce_for_validation_skip` Config — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's stateful validator defines a configurable `max_nonce_for_validation_skip` field in `StatefulTransactionValidatorConfig` but the free function `skip_stateful_validations` hardcodes `Nonce(Felt::ONE)` instead of reading that field. The config value is dead code in the Rust gateway path. Any operator-set value above `1` is silently ignored, causing valid invoke transactions from undeployed accounts with nonce > 1 to be rejected at the `__validate__` entry point.

### Finding Description

`StatefulTransactionValidatorConfig` declares and documents `max_nonce_for_validation_skip`: [1](#0-0) 

The field is also exposed in the production schema: [2](#0-1) 

However, the free function `skip_stateful_validations` — which decides whether to skip the `__validate__` entry point for the deploy-account + invoke UX flow — hardcodes `Nonce(Felt::ONE)` directly: [3](#0-2) 

The caller `run_pre_validation_checks` has access to `self.config` but never passes `self.config.max_nonce_for_validation_skip` to the function: [4](#0-3) 

By contrast, the Python/native-blockifier path (`PyValidator`) correctly consults the equivalent field: [5](#0-4) 

The two paths are therefore inconsistent: the Python path respects the configured threshold; the Rust gateway path ignores it entirely.

### Impact Explanation

When `max_nonce_for_validation_skip` is set above `1` (e.g., `5`), a user who submits `deploy_account` (nonce 0) followed by invoke transactions at nonces 2–5 will have those invokes rejected at the `__validate__` entry point. The account does not yet exist on-chain, so `__validate__` fails. The gateway should have skipped validation for those nonces (because the deploy is pending in the mempool), but the hardcoded `Nonce(Felt::ONE)` check prevents the skip. Valid transactions are rejected before sequencing.

Impact: **High — Mempool/gateway admission rejects valid transactions before sequencing.**

### Likelihood Explanation

The default value of `max_nonce_for_validation_skip` is `Nonce(Felt::ONE)`, which coincidentally matches the hardcoded constant, so the bug is invisible with default configuration. The issue surfaces only when an operator raises the threshold — a plausible operational change given the field is documented and schema-exposed. The discrepancy with the Python path makes an accidental misconfiguration likely.

### Recommendation

Convert `skip_stateful_validations` into a method on `StatefulTransactionValidator` (or pass the threshold as a parameter) and replace the hardcoded `Nonce(Felt::ONE)` with `self.config.max_nonce_for_validation_skip`:

```rust
// In run_pre_validation_checks:
let skip_validate = self.skip_stateful_validations(
    executable_tx,
    account_nonce,
    mempool_client.clone(),
).await?;

// In skip_stateful_validations (now a method):
if tx.nonce() <= self.config.max_nonce_for_validation_skip
    && account_nonce == Nonce(Felt::ZERO)
{
    // existing mempool check …
}
```

### Proof of Concept

1. Configure the gateway with `max_nonce_for_validation_skip = Nonce(5)`.
2. Submit a `DeployAccount` for a fresh address `A` (nonce 0). It enters the mempool; `account_tx_in_pool_or_recent_block(A)` returns `true`.
3. Submit an `Invoke` from `A` with nonce `2`.
4. `validate_nonce` passes (nonce 2 is within `max_allowed_nonce_gap = 200`).
5. `validate_by_mempool` passes (mempool accepts the future nonce).
6. `skip_stateful_validations` evaluates `tx.nonce() == Nonce(Felt::ONE)` → `false` (nonce is 2), so `skip_validate = false`.
7. `run_validate_entry_point` runs `__validate__` on the non-existent account → `ValidateFailure`.
8. **Expected**: validation skipped (nonce 2 ≤ configured threshold 5, deploy pending). **Actual**: transaction rejected. [6](#0-5) [7](#0-6)

### Citations

**File:** crates/apollo_gateway_config/src/config.rs (L276-299)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, Validate, PartialEq)]
pub struct StatefulTransactionValidatorConfig {
    // If true, ensures the max L2 gas price exceeds (a configurable percentage of) the base gas
    // price of the previous block.
    pub validate_resource_bounds: bool,
    pub max_allowed_nonce_gap: u32,
    pub reject_future_declare_txs: bool,
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

**File:** crates/apollo_node/resources/config_schema.json (L3107-3110)
```json
  "gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip": {
    "description": "Maximum nonce for which the validation is skipped.",
    "privacy": "Public",
    "value": "0x1"
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

**File:** crates/native_blockifier/src/py_validator.rs (L112-120)
```rust
        let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;

        Ok(!skip_validate)
```
