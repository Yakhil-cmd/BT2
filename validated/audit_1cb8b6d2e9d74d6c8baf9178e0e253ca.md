### Title
`skip_stateful_validations` hardcodes `Nonce(Felt::ONE)` but ignores `max_nonce_for_validation_skip` config, causing admission to accept or reject transactions contrary to operator intent - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The Apollo gateway's `skip_stateful_validations` function hardcodes `Nonce(Felt::ONE)` as the exact nonce for which `__validate__` is skipped on undeployed accounts. The `StatefulTransactionValidatorConfig` carries a `max_nonce_for_validation_skip` field that is supposed to govern this threshold, but that field is **never read** inside `skip_stateful_validations`. The reference implementation in `native_blockifier/src/py_validator.rs` (`PyValidator::should_run_stateful_validations`) correctly uses `tx_nonce <= self.max_nonce_for_validation_skip`. The mismatch means the config knob is silently dead, producing two distinct admission errors depending on how an operator sets it.

### Finding Description

`skip_stateful_validations` in the Apollo gateway stateful path:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  line 437
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
``` [1](#0-0) 

The condition is an **exact equality** against the literal `Nonce(Felt::ONE)`. The config struct that is passed into every `StatefulTransactionValidator` instance defines:

```rust
pub max_nonce_for_validation_skip: Nonce,  // default Nonce(Felt::ONE)
``` [2](#0-1) 

The field is documented as "Maximum nonce for which the validation is skipped." The legacy Python-bridge validator (`PyValidator`) implements the intended semantics correctly:

```rust
let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
let nonce_small_enough_to_qualify_for_validation_skip =
    tx_nonce <= self.max_nonce_for_validation_skip;
let skip_validate = deploy_account_not_processed
    && is_post_deploy_nonce
    && nonce_small_enough_to_qualify_for_validation_skip;
``` [3](#0-2) 

The Apollo gateway's `skip_stateful_validations` never references `self.config.max_nonce_for_validation_skip`. The config field is defined, serialised, and shipped in `config_schema.json` with a live default of `0x1`, but has zero effect on the gateway's admission decision. [4](#0-3) 

### Impact Explanation

Two distinct broken invariants arise depending on the operator's config:

**Case A — operator sets `max_nonce_for_validation_skip = 0` to disable the UX bypass:**
`skip_stateful_validations` still fires for any invoke tx with `nonce == 1` and `account_nonce == 0` when `account_tx_in_pool_or_recent_block` returns `true`. The gateway skips `__validate__` on an undeployed account even though the operator explicitly disabled this path. An invoke transaction that should be rejected (because the operator turned off the bypass) is admitted without running the account's `__validate__` entry point.

**Case B — operator sets `max_nonce_for_validation_skip > 1` (e.g., 5) to extend the UX window:**
Only `nonce == 1` ever triggers the skip. Invoke transactions with nonces 2–5 for an undeployed account reach `run_validate_entry_point`, which calls `__validate__` on a contract that does not yet exist. The blockifier returns a `ValidateFailure` error and the gateway rejects the transaction. Valid transactions that the operator intended to admit are rejected.

Both cases fall under **High** impact: "Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."

### Likelihood Explanation

The default value of `max_nonce_for_validation_skip` is `Nonce(Felt::ONE)`, which coincidentally matches the hardcoded literal, so the bug is invisible at default configuration. Any operator who reads the documented field name and adjusts it — either to `0` to harden the node or to `> 1` to widen the UX window — will silently get the wrong behaviour. The config is present in the production `config_schema.json` and deployment app configs, making operator adjustment a realistic event.

### Recommendation

Replace the hardcoded literal in `skip_stateful_validations` with the config value, mirroring `PyValidator`:

```rust
// pass config into the free function, or make it a method
if account_nonce == Nonce(Felt::ZERO)
    && tx.nonce() >= Nonce(Felt::ONE)
    && tx.nonce() <= config.max_nonce_for_validation_skip
{
    // existing mempool check …
}
``` [5](#0-4) 

### Proof of Concept

**Scenario A (bypass persists when disabled):**
1. Deploy the sequencer with `max_nonce_for_validation_skip = 0x0`.
2. Submit a `deploy_account` tx for address `A`; it enters the mempool.
3. Submit an `invoke` tx from `A` with `nonce = 1`.
4. `validate_nonce` passes (1 ≤ 0 + 200).
5. `skip_stateful_validations` evaluates `1 == 1 && 0 == 0` → `true`; `account_tx_in_pool_or_recent_block` returns `true`.
6. `__validate__` is skipped. The invoke tx is admitted without signature verification, contrary to the operator's intent.

**Scenario B (valid tx rejected when window extended):**
1. Deploy the sequencer with `max_nonce_for_validation_skip = 0x5`.
2. Submit a `deploy_account` tx for address `A`; it enters the mempool.
3. Submit an `invoke` tx from `A` with `nonce = 3`.
4. `validate_nonce` passes (3 ≤ 0 + 200).
5. `skip_stateful_validations` evaluates `3 == 1` → `false`; returns `false` (do not skip).
6. `run_validate_entry_point` calls `__validate__` on the not-yet-deployed account; blockifier returns `ValidateFailure`.
7. The gateway rejects the transaction. The operator intended nonces 1–5 to be admitted without `__validate__`; only nonce 1 is. [1](#0-0) [6](#0-5) [7](#0-6)

### Citations

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

**File:** crates/native_blockifier/src/py_validator.rs (L98-121)
```rust
    pub fn should_run_stateful_validations(
        &mut self,
        account_tx: &AccountTransaction,
        deploy_account_tx_hash: Option<TransactionHash>,
    ) -> StatefulValidatorResult<bool> {
        if account_tx.tx_type() != TransactionType::InvokeFunction {
            return Ok(true);
        }
        let tx_info = account_tx.create_tx_info();
        let nonce = self.stateful_validator.get_nonce(tx_info.sender_address())?;

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

**File:** crates/apollo_node/resources/config_schema.json (L3107-3111)
```json
  "gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip": {
    "description": "Maximum nonce for which the validation is skipped.",
    "privacy": "Public",
    "value": "0x1"
  },
```
