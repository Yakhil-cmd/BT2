### Title
`skip_stateful_validations` Ignores `max_nonce_for_validation_skip` Config, Hardcoding Nonce-1 Skip Condition — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `StatefulTransactionValidatorConfig` exposes a `max_nonce_for_validation_skip` field that is documented as "Maximum nonce for which the validation is skipped." The field is correctly consumed in the legacy Python-based gateway path (`PyValidator::should_run_stateful_validations`), but in the production Rust gateway path the free function `skip_stateful_validations` hardcodes the bound to `Nonce(Felt::ONE)` and never receives the config value. The result is a split-brain: the operator can set `max_nonce_for_validation_skip` to any value, but the Rust gateway always behaves as if it is `1`, silently ignoring the configured bound in both directions.

### Finding Description

`StatefulTransactionValidatorConfig` declares and serializes `max_nonce_for_validation_skip`: [1](#0-0) 

The legacy Python path reads and applies it correctly: [2](#0-1) 

In the Rust gateway path, `run_pre_validation_checks` calls the free function `skip_stateful_validations` without forwarding the config: [3](#0-2) 

Inside `skip_stateful_validations`, the bound is hardcoded to `Nonce(Felt::ONE)` regardless of what the operator configured: [4](#0-3) 

The function signature accepts no config parameter, so there is no path by which `self.config.max_nonce_for_validation_skip` can reach the check: [5](#0-4) 

This is the direct analog of the external M-18 bug: one variable (`gaugeWeight`) was adjusted by the delta while a correlated variable (`totalWeight`) was left stale, producing an incorrect "what-if" result. Here, the config-supplied bound is the "delta" that should govern the skip window, but it is never applied to the hardcoded check, so the check always evaluates against the wrong (stale) value.

### Impact Explanation

**Direction 1 — config set to `0` (operator disables the skip entirely):**  
`skip_stateful_validations` still returns `true` for any invoke transaction with `nonce == 1` whose sender has a `deploy_account` in the mempool or a recent block. `run_validate_entry_point` is then called with `validate = false`, meaning `__validate__` is never executed at the gateway. An attacker who controls a fresh account can submit an invoke at nonce 1 carrying an invalid signature (or any payload that would fail `__validate__`), and the gateway admits it to the mempool without running the account's validation logic — directly contradicting the operator's intent to always validate.

**Direction 2 — config set to `N > 1` (operator widens the skip window):**  
Invoke transactions with nonces `2 … N` that arrive while the deploy_account is still pending are not skipped; they fail the hardcoded `nonce == 1` test and are sent through `run_validate_entry_point` with `validate = true`. Because the account does not yet exist on-chain, `__validate__` fails and the gateway rejects transactions that should have been admitted — a valid-transaction-rejection admission failure.

Both directions match the allowed impact scope: *"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

The default value of `max_nonce_for_validation_skip` is `Nonce(Felt::ONE)`, which coincidentally matches the hardcoded constant, so the bug is latent under the default deployment. However:

- The field is fully serialized, documented, and exposed in `config_schema.json` and the deployment JSON configs, signalling operator-facing configurability.
- The Python path already implements the general bound, so operators familiar with that path may reasonably expect the Rust path to honour the same knob.
- Any operator who sets the field to `0` to harden the gateway, or to `> 1` to improve UX for multi-step account deployments, will silently get the wrong behaviour with no error or warning.

### Recommendation

Convert `skip_stateful_validations` from a free function into a method on `StatefulTransactionValidator` (or pass `max_nonce_for_validation_skip` as an explicit parameter), and replace the hardcoded `Nonce(Felt::ONE)` with the configured bound:

```rust
// In run_pre_validation_checks, pass the config value:
let skip_validate = skip_stateful_validations(
    executable_tx,
    account_nonce,
    mempool_client.clone(),
    self.config.max_nonce_for_validation_skip,   // ← add this
).await?;

// In skip_stateful_validations, use it:
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
    max_nonce_for_validation_skip: Nonce,        // ← add this
) -> ... {
    if let ExecutableTransaction::Invoke(...) = tx {
        let tx_nonce = tx.nonce();
        if account_nonce == Nonce(Felt::ZERO)
            && tx_nonce >= Nonce(Felt::ONE)
            && tx_nonce <= max_nonce_for_validation_skip   // ← use it
        {
            ...
        }
    }
    Ok(false)
}
```

Add a test that sets `max_nonce_for_validation_skip = Nonce(Felt::ZERO)` and verifies that an invoke at nonce 1 is **not** skipped, mirroring the existing `test_skip_validate` cases.

### Proof of Concept

1. Deploy the Rust gateway with `max_nonce_for_validation_skip = "0x0"` in `gateway_config.json`.
2. Submit a `deploy_account` transaction for a fresh account `A`; it enters the mempool.
3. Submit an `invoke` transaction from `A` at nonce `1` with a deliberately invalid signature.
4. `skip_stateful_validations` evaluates `tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO)` → `true`; `account_tx_in_pool_or_recent_block` returns `true` (the deploy_account is in the pool).
5. `run_validate_entry_point` is called with `validate = false`; `__validate__` is never run.
6. The invalid invoke is admitted to the mempool — contradicting the operator's `max_nonce_for_validation_skip = 0` intent.

The root cause is at: [6](#0-5) 

where `Nonce(Felt::ONE)` is hardcoded instead of reading `self.config.max_nonce_for_validation_skip`, while the config field itself is defined but never forwarded: [7](#0-6)

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

**File:** crates/native_blockifier/src/py_validator.rs (L112-118)
```rust
        let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
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
