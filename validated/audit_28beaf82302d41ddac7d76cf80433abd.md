### Title
`max_nonce_for_validation_skip` Config Field Is Never Read by Gateway — Validation-Skip Behavior Cannot Be Disabled - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

`StatefulTransactionValidatorConfig` exposes a `max_nonce_for_validation_skip` field that is serialized, deserialized, and documented as controlling the maximum nonce for which `__validate__` is skipped. However, the gateway's `skip_stateful_validations` function never reads this field — it hardcodes `Nonce(Felt::ONE)` unconditionally. An operator who sets `max_nonce_for_validation_skip = Nonce(Felt::ZERO)` to disable the skip (e.g., for security hardening) will have that configuration silently ignored, and the gateway will continue to admit invoke transactions with nonce=1 without running `__validate__`.

### Finding Description

`StatefulTransactionValidatorConfig` declares:

```rust
pub max_nonce_for_validation_skip: Nonce,
```

with default `Nonce(Felt::ONE)` and a `dump()` description of "Maximum nonce for which the validation is skipped." [1](#0-0) 

The gateway's stateful validation path calls `skip_stateful_validations`, a free function that receives no reference to `self.config`:

```rust
let skip_validate =
    skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
``` [2](#0-1) 

Inside `skip_stateful_validations`, the nonce threshold is hardcoded to `Nonce(Felt::ONE)`:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
``` [3](#0-2) 

`max_nonce_for_validation_skip` is never passed to, nor read by, this function. The field is present in the config struct, serialized to the config schema, and can be set by operators — but has zero effect on runtime behavior.

By contrast, the native-blockifier path (`PyValidator::should_run_stateful_validations`) does read an equivalent field:

```rust
let nonce_small_enough_to_qualify_for_validation_skip =
    tx_nonce <= self.max_nonce_for_validation_skip;
``` [4](#0-3) 

This confirms the field was intended to be configurable but was never wired into the gateway path.

### Impact Explanation

When `skip_validate = true`, `run_validate_entry_point` is called with `validate: false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [5](#0-4) 

With `validate: false`, `AccountTransaction::validate_tx` returns `Ok(None)` immediately — the account's `__validate__` entry point (which performs signature verification) is never called:

```rust
if !self.execution_flags.validate {
    return Ok(None);
}
``` [6](#0-5) 

An invoke transaction with nonce=1 and a completely invalid/forged signature is therefore admitted to the mempool without any signature check, as long as a deploy_account for that sender is present in the mempool or a recent block.

An operator who sets `max_nonce_for_validation_skip = Nonce(Felt::ZERO)` to close this window cannot do so — the gateway ignores the field and the skip remains active.

### Likelihood Explanation

The trigger is unprivileged: any user can submit an invoke transaction with nonce=1 targeting an account whose deploy_account is pending. The mempool check (`account_tx_in_pool_or_recent_block`) is the only guard, and it returns `true` whenever the account has any transaction in the pool or a recent block — a condition an attacker can arrange by submitting their own deploy_account first.

### Recommendation

Pass `self.config.max_nonce_for_validation_skip` into `skip_stateful_validations` and replace the hardcoded `Nonce(Felt::ONE)` with the configured value:

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    max_nonce_for_validation_skip: Nonce,   // <-- add parameter
    mempool_client: SharedMempoolClient,
) -> ... {
    if let ExecutableTransaction::Invoke(...) = tx {
        if tx.nonce() <= max_nonce_for_validation_skip   // <-- use config
            && account_nonce == Nonce(Felt::ZERO) { ...
```

Update the call site in `run_pre_validation_checks` to pass `self.config.max_nonce_for_validation_skip`.

### Proof of Concept

1. Deploy an account contract `A` on a testnet node running this sequencer.
2. Submit a `DeployAccount` transaction for a new account `B` (nonce=0). Confirm it is in the mempool (`account_tx_in_pool_or_recent_block` returns `true`).
3. Set `max_nonce_for_validation_skip = Nonce(Felt::ZERO)` in the node config (intending to disable the skip).
4. Submit an `Invoke` transaction from `B` with nonce=1 and a garbage signature (e.g., all zeros).
5. Observe: the gateway calls `skip_stateful_validations`, which hardcodes `Nonce(Felt::ONE)`, returns `true`, and the transaction is admitted to the mempool without `__validate__` being called — despite the operator's explicit configuration to disable this behavior.
6. Confirm by checking that `run_validate_entry_point` is invoked with `validate: false` and no `__validate__` call appears in execution traces.

### Citations

**File:** crates/apollo_gateway_config/src/config.rs (L276-300)
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-458)
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
```

**File:** crates/native_blockifier/src/py_validator.rs (L113-118)
```rust
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
```
