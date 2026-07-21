### Title
`max_nonce_for_validation_skip` Config Field Ignored in Gateway Validation-Skip Logic — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidatorConfig` declares a `max_nonce_for_validation_skip` field that is documented as controlling the maximum transaction nonce for which the `__validate__` entry-point call is skipped. The field is serialised, deployed, and has a default of `Nonce(Felt::ONE)`. However, the free function `skip_stateful_validations` that implements this logic never receives the config value and instead hard-codes the check `tx.nonce() == Nonce(Felt::ONE)`. The config field is therefore dead code in the production gateway path: any operator-supplied value is silently ignored.

---

### Finding Description

**Config field — defined but never consumed**

`StatefulTransactionValidatorConfig` declares:

```rust
pub max_nonce_for_validation_skip: Nonce,   // default Nonce(Felt::ONE)
``` [1](#0-0) 

The field is serialised and shipped in every deployment config, with the description *"Maximum nonce for which the validation is skipped."* [2](#0-1) 

**Gateway skip function — hard-coded constant**

The free function `skip_stateful_validations` takes no config argument and hard-codes the threshold:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
``` [3](#0-2) 

`run_pre_validation_checks` calls it without forwarding `self.config.max_nonce_for_validation_skip`:

```rust
let skip_validate =
    skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
``` [4](#0-3) 

**Correct reference implementation exists in `PyValidator`**

The legacy Python-binding validator (`native_blockifier`) stores the field on the struct and uses it correctly:

```rust
let nonce_small_enough_to_qualify_for_validation_skip =
    tx_nonce <= self.max_nonce_for_validation_skip;

let skip_validate = deploy_account_not_processed
    && is_post_deploy_nonce
    && nonce_small_enough_to_qualify_for_validation_skip;
``` [5](#0-4) 

The new Rust gateway never ported this config-driven check; it regressed to a hard-coded constant.

**Structural parallel to the reported Solidity bug**

| Solidity bug | Rust analog |
|---|---|
| Child re-declares `_customFees`; parent functions read parent's (empty) mapping | `skip_stateful_validations` ignores `config.max_nonce_for_validation_skip`; reads hard-coded `Nonce(Felt::ONE)` |
| Setter in child never called → custom fee logic dead | Config field serialised and deployed → skip-threshold logic dead |
| `newNativeTokenVestingManager()` always uses `defaultGasFee` | Gateway always skips validation at nonce=1 regardless of configured threshold |

---

### Impact Explanation

`skip_stateful_validations` returning `true` causes `run_validate_entry_point` to set `validate: false` in `ExecutionFlags`, which suppresses the `__validate__` entry-point call entirely for that transaction at the gateway level. [6](#0-5) 

Because the config field is never read:

1. **Operator sets `max_nonce_for_validation_skip = 0`** (intending to disable the skip entirely for security hardening) — the gateway still skips `__validate__` for every nonce-1 invoke whose account has a `deploy_account` in the mempool. An attacker can submit a nonce-1 invoke with an **invalid signature** and it is admitted to the mempool without signature verification.

2. **Operator sets `max_nonce_for_validation_skip = 2`** (intending to extend the UX window) — the gateway still only skips at nonce=1; nonce-2 invokes are incorrectly rejected or validated, breaking the intended UX guarantee.

The admitted invalid-signature transaction will revert during blockifier execution, but it has already passed gateway admission and entered the mempool — satisfying the "accepts invalid transactions before sequencing" impact criterion.

---

### Likelihood Explanation

- The field is present in every deployed gateway config file and is documented as operator-tunable.
- An operator who reads the documentation and sets the field to `0` to tighten security receives no error and no warning; the change is silently ignored.
- The attacker trigger is unprivileged: submit a `deploy_account` for a fresh address, then submit a nonce-1 invoke with a garbage signature. No special access is required.

---

### Recommendation

Convert `skip_stateful_validations` from a free function to a method (or pass the threshold explicitly) and replicate the `PyValidator` logic:

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    max_nonce_for_validation_skip: Nonce,   // ← add parameter
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        let tx_nonce = tx.nonce();
        if account_nonce == Nonce(Felt::ZERO)
            && Nonce(Felt::ONE) <= tx_nonce
            && tx_nonce <= max_nonce_for_validation_skip   // ← use config
        {
            // existing mempool check …
        }
    }
    Ok(false)
}
```

Call site in `run_pre_validation_checks` should pass `self.config.max_nonce_for_validation_skip`.

---

### Proof of Concept

1. Deploy the gateway with `max_nonce_for_validation_skip = 0x0` in `gateway_config.json`.
2. Submit a valid `deploy_account` transaction for a fresh address `A` (account nonce on-chain = 0).
3. Before the `deploy_account` is included in a block, submit an `invoke` transaction from `A` with `nonce = 1` and a **random/invalid signature**.
4. `skip_stateful_validations` evaluates `tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO)` → `true`; `account_tx_in_pool_or_recent_block` returns `true` (step 2 is in the pool).
5. `run_validate_entry_point` is called with `validate: false`; the `__validate__` entry point is **not** executed.
6. The gateway returns a transaction hash and forwards the invalid-signature invoke to the mempool — despite the operator having configured `max_nonce_for_validation_skip = 0` to prevent exactly this bypass. [3](#0-2) [7](#0-6)

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

**File:** crates/apollo_gateway_config/src/config.rs (L312-317)
```rust
            ser_param(
                "max_nonce_for_validation_skip",
                &self.max_nonce_for_validation_skip,
                "Maximum nonce for which the validation is skipped.",
                ParamPrivacyInput::Public,
            ),
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-356)
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
    }
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

**File:** crates/native_blockifier/src/py_validator.rs (L109-120)
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
```
