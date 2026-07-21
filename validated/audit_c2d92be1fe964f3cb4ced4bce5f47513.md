### Title
`max_nonce_for_validation_skip` Config Field Silently Ignored in Gateway `skip_stateful_validations`, Allowing `__validate__` Bypass Outside Configured Nonce Bound — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidatorConfig` exposes a `max_nonce_for_validation_skip` field that is meant to bound the nonce range for which the gateway may skip the `__validate__` entry-point call on incoming invoke transactions. The field is loaded from deployment config, serialised, and correctly consumed in the `PyValidator` (native-blockifier) path. However, the production Rust gateway path's `skip_stateful_validations` free function never reads this field; it hardcodes `Nonce(Felt::ONE)` unconditionally. When an operator sets `max_nonce_for_validation_skip = 0` to disable the skip feature entirely, the gateway ignores the setting and continues to skip `__validate__` for every invoke with `nonce == 1`, admitting transactions whose signatures have never been verified.

### Finding Description

`StatefulTransactionValidatorConfig` declares the field:

```rust
pub max_nonce_for_validation_skip: Nonce,   // default Nonce(Felt::ONE)
``` [1](#0-0) 

The deployment config file ships this field as a live, operator-visible parameter:

```json
"gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip": "0x1"
``` [2](#0-1) 

In the `PyValidator` (native-blockifier) path the field is correctly used as an upper bound:

```rust
let nonce_small_enough_to_qualify_for_validation_skip =
    tx_nonce <= self.max_nonce_for_validation_skip;
let skip_validate = deploy_account_not_processed
    && is_post_deploy_nonce
    && nonce_small_enough_to_qualify_for_validation_skip;
``` [3](#0-2) 

In the production Rust gateway path, `skip_stateful_validations` is a free function that receives no config argument and hardcodes the bound:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
``` [4](#0-3) 

`StatefulTransactionValidator` holds `self.config` but never passes `max_nonce_for_validation_skip` into `skip_stateful_validations`:

```rust
let skip_validate =
    skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
``` [5](#0-4) 

When `skip_validate == true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [6](#0-5) 

Inside `StatefulValidator::perform_validations`, an invoke transaction with `validate == false` returns `Ok(())` immediately, before `__validate__` is ever called:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
``` [7](#0-6) 

### Impact Explanation

If an operator sets `max_nonce_for_validation_skip = 0` to disable the UX-skip feature, the gateway ignores the setting. Any attacker who has a `deploy_account` transaction in the mempool (trivially self-submitted) can then submit an invoke transaction with `nonce = 1` carrying an arbitrary or absent signature. The gateway's `skip_stateful_validations` fires, `__validate__` is never called, and the transaction is forwarded to the mempool and ultimately to the batcher without any signature check at the admission layer. This matches **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing**.

### Likelihood Explanation

The current production deployment config sets `max_nonce_for_validation_skip = 0x1`, which coincidentally equals the hardcoded constant, so the bug is dormant today. However, the field is a documented, public, operator-configurable parameter. Any operator who sets it to `0` to tighten security activates the discrepancy. The attacker-controlled steps (submit own `deploy_account`, submit invoke with bad signature, nonce=1) require no privilege.

### Recommendation

Pass `max_nonce_for_validation_skip` from `StatefulTransactionValidatorConfig` into `skip_stateful_validations` and replace the hardcoded equality check with the same two-sided range check used in `PyValidator`:

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    max_nonce_for_validation_skip: Nonce,   // ← add parameter
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        let tx_nonce = tx.nonce();
        let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
        let within_skip_range = tx_nonce <= max_nonce_for_validation_skip;
        if is_post_deploy_nonce && within_skip_range && account_nonce == Nonce(Felt::ZERO) {
            // existing mempool check …
        }
    }
    Ok(false)
}
```

Call site in `run_pre_validation_checks` should pass `self.config.max_nonce_for_validation_skip`.

### Proof of Concept

1. Operator deploys gateway with `max_nonce_for_validation_skip = 0` (intending to disable the skip).
2. Attacker calls `add_tx` with a valid `DeployAccount` for address `A`; it passes all checks and enters the mempool.
3. Attacker calls `add_tx` with an `Invoke` from address `A`, `nonce = 1`, signature = `[]` (empty / invalid).
4. `validate_nonce` passes (nonce 1 is within `max_allowed_nonce_gap = 200` of account nonce 0).
5. `skip_stateful_validations` fires: `tx.nonce() == Nonce(Felt::ONE)` ✓, `account_nonce == Nonce(Felt::ZERO)` ✓, `account_tx_in_pool_or_recent_block` returns `true` ✓ → returns `true`.
6. `run_validate_entry_point` is called with `skip_validate = true`; `execution_flags.validate = false`; `StatefulValidator::perform_validations` returns `Ok(())` without ever invoking `__validate__`.
7. The unsigned invoke transaction is admitted to the mempool. The operator's intent to disable the skip is silently overridden.

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

**File:** crates/apollo_deployments/resources/app_configs/gateway_config.json (L18-18)
```json
  "gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip": "0x1",
```

**File:** crates/native_blockifier/src/py_validator.rs (L113-118)
```rust
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L407-408)
```rust
        let skip_validate =
            skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L437-437)
```rust
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```
