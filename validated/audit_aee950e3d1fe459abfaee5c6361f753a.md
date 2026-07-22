### Title
`max_nonce_for_validation_skip` config field silently ignored in gateway `skip_stateful_validations` — `__validate__` entry-point bypass cannot be disabled by operator — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidatorConfig.max_nonce_for_validation_skip` is declared, serialized into the production config schema under `gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip`, and described as *"Maximum nonce for which the validation is skipped."* However, the gateway's `skip_stateful_validations` function never reads this field; it hardcodes the nonce threshold to `Nonce(Felt::ONE)`. An operator who sets the field to `0x0` to disable the UX-skip cannot prevent the gateway from admitting Invoke transactions with nonce = 1 without running the account's `__validate__` entry point (i.e., without verifying the signature).

---

### Finding Description

**Root cause — hardcoded threshold instead of config read.**

`skip_stateful_validations` is a free function that receives no reference to `StatefulTransactionValidatorConfig`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 429-460
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
``` [1](#0-0) 

The check `tx.nonce() == Nonce(Felt::ONE)` is unconditional. The config field `max_nonce_for_validation_skip` is never passed in and never consulted.

**Config field that implies control but has none.**

`StatefulTransactionValidatorConfig` declares and serializes the field:

```rust
// crates/apollo_gateway_config/src/config.rs  lines 276-300
pub struct StatefulTransactionValidatorConfig {
    ...
    pub max_nonce_for_validation_skip: Nonce,
    ...
}
impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            ...
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
            ...
        }
    }
}
``` [2](#0-1) 

The production config schema exposes it publicly:

```json
"gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip": {
    "description": "Maximum nonce for which the validation is skipped.",
    "privacy": "Public",
    "value": "0x1"
}
``` [3](#0-2) 

**Contrast with the native-blockifier path that does use the field.**

`PyValidator.should_run_stateful_validations` correctly reads `self.max_nonce_for_validation_skip`:

```rust
// crates/native_blockifier/src/py_validator.rs  lines 112-118
let nonce_small_enough_to_qualify_for_validation_skip =
    tx_nonce <= self.max_nonce_for_validation_skip;
let skip_validate = deploy_account_not_processed
    && is_post_deploy_nonce
    && nonce_small_enough_to_qualify_for_validation_skip;
``` [4](#0-3) 

The gateway path never does the equivalent.

**How the skip suppresses signature verification.**

`run_pre_validation_checks` returns the boolean from `skip_stateful_validations`: [5](#0-4) 

`extract_state_nonce_and_run_validations` passes it to `run_validate_entry_point`: [6](#0-5) 

`run_validate_entry_point` sets `validate: !skip_validate`: [7](#0-6) 

`StatefulValidator::perform_validations` returns early without calling `__validate__` when `validate` is false:

```rust
// crates/blockifier/src/blockifier/stateful_validator.rs  lines 79-81
if !tx.execution_flags.validate {
    return Ok(());
}
``` [8](#0-7) 

The account signature is therefore **never verified** at the gateway level for any Invoke with nonce = 1 from an undeployed account that has a deploy-account in the mempool — regardless of what `max_nonce_for_validation_skip` is set to.

---

### Impact Explanation

An operator who sets `max_nonce_for_validation_skip = 0x0` to disable the UX-skip (e.g., for a permissioned deployment that does not want unvalidated transactions admitted) cannot achieve that goal. The gateway will still admit Invoke transactions with nonce = 1 and an **arbitrary or invalid signature** into the mempool, provided the sender address has a deploy-account transaction in the mempool or a recent block. This satisfies the "High" impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."*

---

### Likelihood Explanation

The default value of `max_nonce_for_validation_skip` is `0x1`, which coincidentally matches the hardcoded threshold, so the discrepancy is invisible in a default deployment. The vulnerability becomes reachable the moment an operator lowers the field to `0x0` — a natural action for any operator who reads the description *"Maximum nonce for which the validation is skipped"* and wants to tighten admission policy. The config field is publicly documented and operator-writable, making accidental misconfiguration plausible.

---

### Recommendation

Pass `self.config.max_nonce_for_validation_skip` into `skip_stateful_validations` (or make it a method on `StatefulTransactionValidator`) and replace the hardcoded equality check with a range check:

```rust
// proposed fix
if tx.nonce() >= Nonce(Felt::ONE)
    && tx.nonce() <= max_nonce_for_validation_skip
    && account_nonce == Nonce(Felt::ZERO)
{
```

This mirrors the logic already present in `PyValidator::should_run_stateful_validations` and makes the config field actually control gateway behavior.

---

### Proof of Concept

1. Deploy the sequencer with `gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip = "0x0"` (operator intends to disable the UX-skip entirely).
2. Submit a valid `DeployAccount` transaction for address `A` — it passes full stateful validation and enters the mempool.
3. Craft an `Invoke` transaction for address `A` with `nonce = 1` and a **garbage signature** (e.g., all-zero felts).
4. Submit the Invoke to the gateway.
5. `skip_stateful_validations` evaluates `tx.nonce() == Nonce(Felt::ONE)` → `true`, `account_nonce == Nonce(Felt::ZERO)` → `true`, `account_tx_in_pool_or_recent_block(A)` → `true` (the deploy-account is in the mempool). It returns `true` regardless of the config value.
6. `run_validate_entry_point` sets `validate = false`; `StatefulValidator` returns `Ok(())` without calling `__validate__`. The Invoke is admitted to the mempool with an unverified signature.
7. During block building, `__validate__` is called and fails; the transaction is rejected from the block — but the mempool has already accepted it, and the operator's intended admission policy was silently violated.

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-315)
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-460)
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
```

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

**File:** crates/apollo_node/resources/config_schema.json (L3107-3111)
```json
  "gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip": {
    "description": "Maximum nonce for which the validation is skipped.",
    "privacy": "Public",
    "value": "0x1"
  },
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
