### Title
`max_nonce_for_validation_skip` Config Field Never Consulted in Gateway — `__validate__` Skip Cannot Be Disabled - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidatorConfig` exposes a `max_nonce_for_validation_skip` field that is documented as "Maximum nonce for which the validation is skipped." The gateway's `skip_stateful_validations` free function never reads this field; it hardcodes the nonce check to `tx.nonce() == Nonce(Felt::ONE)`. An operator who sets `max_nonce_for_validation_skip = 0` to disable the skip feature entirely cannot do so: the gateway will still admit invoke transactions with nonce 1 without running `__validate__`, regardless of the configured value.

---

### Finding Description

`StatefulTransactionValidatorConfig` declares the field:

```rust
pub max_nonce_for_validation_skip: Nonce,
```

with default `Nonce(Felt::ONE)` and serialization description `"Maximum nonce for which the validation is skipped."` [1](#0-0) 

The legacy `PyValidator::should_run_stateful_validations` in `native_blockifier` correctly consults this field:

```rust
let nonce_small_enough_to_qualify_for_validation_skip =
    tx_nonce <= self.max_nonce_for_validation_skip;
let skip_validate = deploy_account_not_processed
    && is_post_deploy_nonce
    && nonce_small_enough_to_qualify_for_validation_skip;
``` [2](#0-1) 

However, the production gateway path calls the free function `skip_stateful_validations`, which takes no config parameter and hardcodes the nonce check:

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
``` [3](#0-2) 

The caller `run_pre_validation_checks` has `&self` (and thus `self.config.max_nonce_for_validation_skip`) but never passes it to `skip_stateful_validations`:

```rust
async fn run_pre_validation_checks(
    &self, ...
) -> StatefulTransactionValidatorResult<bool> {
    self.validate_state_preconditions(executable_tx, account_nonce).await?;
    validate_by_mempool(executable_tx, account_nonce, mempool_client.clone()).await?;
    let skip_validate =
        skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
    Ok(skip_validate)
}
``` [4](#0-3) 

A `grep` across the entire repository confirms `max_nonce_for_validation_skip` never appears in `crates/apollo_gateway/` at all — only in `native_blockifier`, the config definition, and deployment JSON files.

The deployed config sets `"gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip": "0x1"`, which is the same as the hardcoded value, so the bug is invisible at the default setting. [5](#0-4) 

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

When an operator sets `max_nonce_for_validation_skip = 0` to enforce strict `__validate__` execution for all transactions (e.g., to harden the gateway against signature-bypass attacks), the gateway ignores the setting. Any invoke transaction with nonce 1 from an account whose deploy_account is already in the mempool will still have its `__validate__` entry point skipped and will be admitted to the mempool. A transaction that would fail `__validate__` (e.g., carrying an invalid signature) is accepted into the mempool without the account contract ever verifying it.

The `run_validate_entry_point` path sets `validate: !skip_validate` in `ExecutionFlags`, so when `skip_validate` is incorrectly `true`, the blockifier's `StatefulValidator::perform_validations` returns `Ok(())` immediately without calling `validate_tx`: [6](#0-5) 

---

### Likelihood Explanation

**High.** The default value of `max_nonce_for_validation_skip` (`0x1`) coincidentally matches the hardcoded `Nonce(Felt::ONE)`, so the bug is silent under the default configuration. Any operator who changes the field to `0x0` to disable the skip feature will find the change has no effect. The discrepancy between the `PyValidator` implementation (which correctly uses the field) and the gateway implementation (which ignores it) makes this easy to miss in review.

---

### Recommendation

Pass `self.config.max_nonce_for_validation_skip` into `skip_stateful_validations` and replace the hardcoded equality check with the range check used in `PyValidator`:

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    max_nonce_for_validation_skip: Nonce,   // <-- add parameter
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        let tx_nonce = tx.nonce();
        if tx_nonce >= Nonce(Felt::ONE)
            && tx_nonce <= max_nonce_for_validation_skip   // replaces hardcoded == ONE
            && account_nonce == Nonce(Felt::ZERO)
        {
            ...
        }
    }
    Ok(false)
}
```

And update the call site in `run_pre_validation_checks` to pass `self.config.max_nonce_for_validation_skip`.

---

### Proof of Concept

1. Deploy the gateway with `max_nonce_for_validation_skip = 0x0` (operator intends to disable the skip feature).
2. Submit a `DeployAccount` transaction for a fresh account `A`; it enters the mempool.
3. Submit an `Invoke` transaction from `A` with nonce `1` and a deliberately invalid signature (one that would cause `__validate__` to return `INVALID`).
4. **Expected (with config respected):** gateway rejects the invoke because `max_nonce_for_validation_skip = 0` means no skip is allowed, so `__validate__` runs and fails.
5. **Actual:** `skip_stateful_validations` ignores the config, sees `tx.nonce() == 1 && account_nonce == 0 && account_in_mempool == true`, returns `true`, and the invoke is admitted to the mempool without `__validate__` running.

The root cause is in `crates/apollo_gateway/src/stateful_transaction_validator.rs` at the `skip_stateful_validations` free function (line 429) and its call site in `run_pre_validation_checks` (line 407–408). [7](#0-6)

### Citations

**File:** crates/apollo_gateway_config/src/config.rs (L283-295)
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
```

**File:** crates/native_blockifier/src/py_validator.rs (L113-118)
```rust
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-437)
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
```

**File:** crates/apollo_deployments/resources/app_configs/gateway_config.json (L18-18)
```json
  "gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip": "0x1",
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```
