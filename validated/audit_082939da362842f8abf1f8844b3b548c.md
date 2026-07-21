### Title
Gateway `skip_stateful_validations` Admits Signature-Bypassed Invoke Transactions for Accounts Deployed via `deploy` Syscall - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway stateful validation path unconditionally skips the `__validate__` entry point (signature verification) for any invoke transaction with `nonce == 1` when `account_nonce == 0` and the account address appears in the mempool. The function assumes that any account present in the mempool with `account_nonce == 0` must have a pending `deploy_account` transaction. This assumption is broken for accounts deployed via the `deploy` syscall (not `deploy_account`), which have `nonce == 0` in committed state but a valid contract class. An attacker who controls such an account can pre-seed the mempool with a valid future-nonce invoke, then submit a `nonce == 1` invoke with an invalid or forged signature that the gateway accepts without running `__validate__`.

### Finding Description

`skip_stateful_validations` is a free function in `crates/apollo_gateway/src/stateful_transaction_validator.rs` called from `run_pre_validation_checks`:

```
run_pre_validation_checks
  → validate_state_preconditions   (nonce range, resource bounds)
  → validate_by_mempool            (mempool-level duplicate/nonce check)
  → skip_stateful_validations      ← decides whether __validate__ runs
```

The function body:

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When this returns `true`, `run_validate_entry_point` sets `validate: false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

And `StatefulValidator::perform_validations` returns `Ok(())` immediately without calling `__validate__`:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
``` [3](#0-2) 

The mempool's `account_tx_in_pool_or_recent_block` returns `true` if the account has **any** transaction in the pool, not specifically a `deploy_account`:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [4](#0-3) 

The code comment acknowledges the assumption but does not enforce it:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction **or transactions with future nonces that passed validations**." [5](#0-4) 

**Attack path:**

1. Attacker deploys contract at address `X` via the `deploy` syscall from another contract. `X` now has a valid contract class and `nonce == 0` in committed state (no `deploy_account` was ever submitted).
2. Attacker submits `Invoke(sender=X, nonce=2)` with a valid signature. `validate_nonce` accepts it (nonce 2 is within `[0, max_allowed_nonce_gap=200]`). `run_validate_entry_point` runs `__validate__` and succeeds. `X` is now present in `tx_pool`.
3. Attacker submits `Invoke(sender=X, nonce=1)` with an **invalid or forged signature**. `validate_nonce` accepts it (nonce 1 is in range). `skip_stateful_validations` fires: `nonce == 1`, `account_nonce == 0`, `account_tx_in_pool_or_recent_block(X) == true` → returns `true`. `run_validate_entry_point` sets `validate=false` and returns `Ok(())` without running `__validate__`. The gateway calls `mempool_client.add_tx(...)` and the invalid transaction enters the mempool.

The `StatefulTransactionValidatorConfig` field `max_nonce_for_validation_skip` (default `0x1`) is serialized and documented but is **never read** by `skip_stateful_validations` in the gateway — the check is hardcoded to `Nonce(Felt::ONE)`. The analogous `PyValidator::should_run_stateful_validations` in `native_blockifier` does consult this field, creating a silent behavioral divergence. [6](#0-5) 
<cite repo

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-314)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

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
