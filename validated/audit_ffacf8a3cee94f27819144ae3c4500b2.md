### Title
`max_nonce_for_validation_skip` Config Field Ignored in Gateway Stateful Validation Skip — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidatorConfig` exposes a `max_nonce_for_validation_skip` field documented as "Maximum nonce for which the validation is skipped." The field is serialized, shipped in the production config schema, and correctly used in the legacy Python path (`PyValidator::should_run_stateful_validations`). However, the Rust gateway's `skip_stateful_validations` free function never reads this field; it hardcodes `Nonce(Felt::ONE)` unconditionally. The config knob is therefore dead code in the production Rust gateway path, making it impossible for operators to either disable or extend the validation-skip window. When an operator sets `max_nonce_for_validation_skip = 0` to disable the skip, the gateway still bypasses `__validate__` for nonce-1 invoke transactions from undeployed accounts, admitting transactions whose signatures have never been verified.

### Finding Description

**Config field definition and default:** [1](#0-0) 

`max_nonce_for_validation_skip` defaults to `Nonce(Felt::ONE)` and is serialized to the production schema at `"0x1"`. [2](#0-1) 

**Correct usage in the Python/native-blockifier path:**

`PyValidator::should_run_stateful_validations` reads `self.max_nonce_for_validation_skip` and uses it as an upper bound:

```rust
let nonce_small_enough_to_qualify_for_validation_skip =
    tx_nonce <= self.max_nonce_for_validation_skip;
let skip_validate = deploy_account_not_processed
    && is_post_deploy_nonce
    && nonce_small_enough_to_qualify_for_validation_skip;
``` [3](#0-2) 

**Dead code in the Rust gateway path:**

`skip_stateful_validations` is a free function — it receives no `config` parameter and hardcodes `Nonce(Felt::ONE)`:

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(...) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await ...;
        }
    }
    Ok(false)
}
``` [4](#0-3) 

The caller `run_pre_validation_checks` passes no config to this function: [5](#0-4) 

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [6](#0-5) 

Inside `StatefulValidator::perform_validations`, `validate = false` causes the `__validate__` entry-point call to be skipped entirely: [7](#0-6) 

`perform_pre_validation_stage` (nonce increment, fee bounds, balance check) still runs, but the account's signature-verification logic is never invoked. [8](#0-7) 

### Impact Explanation

Two concrete failure modes arise when the config is changed from its default:

**Mode A — operator sets `max_nonce_for_validation_skip = 0` to disable the skip:**  
The hardcoded `== Nonce(Felt::ONE)` check still fires. Any invoke transaction with nonce 1 from an undeployed account whose deploy_account is in the mempool bypasses `__validate__`. The gateway admits the transaction without verifying the account's signature. The transaction enters the mempool and will only fail (revert) at execution time, wasting sequencer resources and constituting unauthorized admission.

**Mode B — operator sets `max_nonce_for_validation_skip > 1` to extend the UX window:**  
The gateway only skips for exactly nonce 1. Invoke transactions with nonces 2 through N from undeployed accounts are rejected even though the config says they should be accepted, breaking the deploy-account+invoke UX flow for those nonces.

Both modes fall under: **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

### Likelihood Explanation

The default value of `max_nonce_for_validation_skip` is `Nonce(Felt::ONE)`, which happens to produce identical behavior to the hardcoded check under default configuration. The bug is therefore latent and only activates when an operator changes the field. Because the field is documented, serialized, and present in the production config schema, operators have a reasonable expectation that changing it will take effect.

### Recommendation

Convert `skip_stateful_validations` from a free function to a method on `StatefulTransactionValidator` (or pass `max_nonce_for_validation_skip` as an explicit parameter), and replace the hardcoded equality check with a range check mirroring the Python path:

```rust
// Instead of:
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {

// Use:
if tx.nonce() >= Nonce(Felt::ONE)
    && tx.nonce() <= self.config.max_nonce_for_validation_skip
    && account_nonce == Nonce(Felt::ZERO)
{
```

Setting `max_nonce_for_validation_skip = Nonce(Felt::ZERO)` should then fully disable the skip.

### Proof of Concept

1. Deploy the sequencer with `max_nonce_for_validation_skip = 0` (operator intent: disable the skip entirely).
2. Pre-fund address `A` (the pre-computed deploy-account address).
3. Submit a `deploy_account` transaction for address `A` — it passes normal validation and enters the mempool; `account_tx_in_pool_or_recent_block(A)` now returns `true`.
4. Craft an `invoke` transaction: `sender = A`, `nonce = 1`, **signature = garbage**.
5. The gateway evaluates `skip_stateful_validations`:
   - `tx.nonce() == Nonce(Felt::ONE)` → `true` (hardcoded, ignores config = 0)
   - `account_nonce == Nonce(Felt::ZERO)` → `true`
   - `account_tx_in_pool_or_recent_block(A)` → `true`
   - Returns `true` (skip).
6. `run_validate_entry_point` sets `execution_flags.validate = false`; `__validate__` is never called.
7. `perform_pre_validation_stage` passes (nonce 1 ≥ 0, fee bounds satisfied, pre-funded balance covers committed bounds).
8. The transaction is forwarded to the mempool with an unverified signature — **invalid transaction admitted**.

The operator's config change (`max_nonce_for_validation_skip = 0`) had zero effect because `skip_stateful_validations` never reads it. [9](#0-8) [10](#0-9)

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

**File:** crates/apollo_node/resources/config_schema.json (L3107-3111)
```json
  "gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip": {
    "description": "Maximum nonce for which the validation is skipped.",
    "privacy": "Public",
    "value": "0x1"
  },
```

**File:** crates/native_blockifier/src/py_validator.rs (L109-121)
```rust
        let deploy_account_not_processed =
            deploy_account_tx_hash.is_some() && nonce == Nonce(Felt::ZERO);
        let tx_nonce = tx_info.nonce();
        let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;

        Ok(!skip_validate)
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-314)
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
