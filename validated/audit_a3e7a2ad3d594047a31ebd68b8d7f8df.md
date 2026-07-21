### Title
Gateway `skip_stateful_validations` Ignores `max_nonce_for_validation_skip` Config, Hardcoding Nonce=1 Skip Threshold - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary
The `max_nonce_for_validation_skip` field in `StatefulTransactionValidatorConfig` is documented as "Maximum nonce for which the validation is skipped" and is exposed in the production config schema, but the gateway's `skip_stateful_validations` function hardcodes the threshold to `Nonce(Felt::ONE)` regardless of the configured value. The config field has zero effect on gateway admission behavior.

### Finding Description
`StatefulTransactionValidatorConfig` declares:

```rust
pub max_nonce_for_validation_skip: Nonce,
```

with default `Nonce(Felt::ONE)`, and the production config schema documents it at `gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip` with description "Maximum nonce for which the validation is skipped."

The gateway's `skip_stateful_validations` function, however, is a standalone free function that never receives the config and hardcodes the threshold:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
```

The `StatefulTransactionValidator` struct holds `self.config.max_nonce_for_validation_skip`, but `run_pre_validation_checks` calls `skip_stateful_validations` as a free function without passing the config value. The field is never read anywhere in the gateway Rust path.

By contrast, the Python-bindings path (`PyValidator::should_run_stateful_validations`) correctly consults the stored value:

```rust
let nonce_small_enough_to_qualify_for_validation_skip =
    tx_nonce <= self.max_nonce_for_validation_skip;
```

The `skip_validate` boolean returned by `skip_stateful_validations` is forwarded directly into `execution_flags.validate = !skip_validate` inside `run_validate_entry_point`, so when the skip fires the `__validate__` entry point is entirely omitted from the gateway-level blockifier call.

### Impact Explanation
**Scenario A – operator sets `max_nonce_for_validation_skip = 0` to disable the skip entirely:**
The gateway still fires the skip for every invoke transaction whose nonce is exactly 1 and whose account nonce is 0, provided a deploy-account transaction exists in the mempool or a recent block. The `__validate__` entry point is not executed at the gateway level; the transaction is forwarded to the mempool without signature/logic validation. The operator's intent to require full validation for all transactions is silently ignored.

**Scenario B – operator sets `max_nonce_for_validation_skip = 2` to extend the UX window:**
The gateway only skips for nonce=1; transactions with nonce=2 from an undeployed account are rejected even though the operator configured them to be accepted. Valid transactions are dropped before sequencing.

Both scenarios fall under **High – Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing**.

### Likelihood Explanation
The default value (`0x1`) coincides with the hardcoded constant, so the bug is invisible in default deployments. Any operator who reads the documented config field and adjusts it—either to tighten or relax the skip window—will silently get the wrong behavior. The field is public, schema-documented, and pointer-targeted in the node config, making accidental misconfiguration plausible.

### Recommendation
Thread `self.config.max_nonce_for_validation_skip` into `skip_stateful_validations` (or make it a method on `StatefulTransactionValidator`) and replace the hardcoded `Nonce(Felt::ONE)` comparisons with the configured value, mirroring the logic already present in `PyValidator::should_run_stateful_validations`:

```rust
// in run_pre_validation_checks, pass the config value:
let skip_validate = skip_stateful_validations(
    executable_tx,
    account_nonce,
    mempool_client.clone(),
    self.config.max_nonce_for_validation_skip,
).await?;

// in skip_stateful_validations:
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
    max_nonce_for_validation_skip: Nonce,
) -> ... {
    if let ExecutableTransaction::Invoke(...) = tx {
        if tx.nonce() <= max_nonce_for_validation_skip
            && tx.nonce() > Nonce(Felt::ZERO)
            && account_nonce == Nonce(Felt::ZERO)
        { ... }
    }
    Ok(false)
}
```

### Proof of Concept

1. Configure the gateway with `max_nonce_for_validation_skip = 0x0` (operator wants no skip).
2. Submit a `DeployAccount` transaction for address `A`; it enters the mempool.
3. Submit an `Invoke` transaction from `A` with `nonce = 1` whose `__validate__` would return an error (e.g., wrong signature for a custom account).
4. `skip_stateful_validations` evaluates `tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO)` → `true`; `account_tx_in_pool_or_recent_block` returns `true` → skip fires.
5. `run_validate_entry_point` sets `execution_flags.validate = false`; `__validate__` is not called; the transaction is forwarded to the mempool.
6. Expected behavior per config: the transaction should have been rejected at the gateway because `max_nonce_for_validation_skip = 0` means no skip is permitted.

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-312)
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

**File:** crates/apollo_node/resources/config_schema.json (L3107-3111)
```json
  "gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip": {
    "description": "Maximum nonce for which the validation is skipped.",
    "privacy": "Public",
    "value": "0x1"
  },
```

**File:** crates/native_blockifier/src/py_validator.rs (L112-121)
```rust
        let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;

        Ok(!skip_validate)
    }
```
