### Title
Gateway `skip_stateful_validations` Bypasses `__validate__` Entry Point When Deploy-Account Has Expired from Mempool — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function skips the `__validate__` entry-point call for an Invoke transaction with nonce=1 whenever `account_tx_in_pool_or_recent_block` returns `true`. That helper returns `true` not only when a deploy-account is currently in the pool, but also when the account is merely present in the mempool's internal state — which persists indefinitely after transactions expire. An attacker who knows an account address whose deploy-account has expired can submit an Invoke with nonce=1 and an arbitrary (invalid) signature, bypass the gateway's only signature-validation step, and have the transaction admitted to the mempool.

### Finding Description

**Broken invariant**: Every Invoke transaction admitted to the mempool must have had its `__validate__` entry point executed at the gateway, unless a deploy-account for the same account is currently live in the pool.

**Root cause — `skip_stateful_validations`** (`stateful_transaction_validator.rs` lines 429–461):

```rust
async fn skip_stateful_validations(...) -> ... {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await ...
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When this returns `true`, `run_validate_entry_point` is called with `validate: false`, so the `__validate__` entry point is never invoked:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

**Root cause — `account_tx_in_pool_or_recent_block`** (`mempool.rs` lines 697–700):

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

The `self.state.contains_account` branch returns `true` for any account that was ever registered in the mempool's internal state — including accounts whose deploy-account transactions have since expired and been evicted from the pool. The mempool state is never cleared of such records, as the test itself acknowledges:

> *"Note that in the future, the Mempool's state may be periodically cleared from records of old committed transactions."* [4](#0-3) 

The code comment in `skip_stateful_validations` claims:

> *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."*

This reasoning is incorrect once the deploy-account has expired: the account remains in `self.state` but no deploy-account is in the pool, so the precondition the comment relies on no longer holds.

**Signature validation path**: `validate_by_mempool` (called before `skip_stateful_validations`) only checks for duplicate transactions and fee escalation — it does not verify signatures. [5](#0-4) 

The sole gateway-level signature check is the `__validate__` entry-point call inside `run_validate_entry_point` → `blockifier_validator.validate(account_tx)`. [6](#0-5) 

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An Invoke transaction carrying an arbitrary (attacker-chosen) signature is admitted to the mempool without any cryptographic validation. The transaction will fail during block execution (either `InvalidNonce` if no deploy-account is committed, or `ValidateFailure` if the account is deployed but the signature is wrong), but it occupies mempool capacity and forces the sequencer to process it during block building. This matches the impact category:

> *"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

**Medium.** The attacker must:
1. Identify an account address whose deploy-account was submitted to the mempool but expired before being committed (observable via the public RPC/mempool snapshot

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L337-354)
```rust
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
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L413-424)
```rust
/// Perform transaction validation by the mempool.
async fn validate_by_mempool(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<()> {
    let validation_args = ValidationArgs::new(tx, account_nonce);
    mempool_client
        .validate_tx(validation_args)
        .await
        .map_err(|err| mempool_client_err_to_deprecated_gw_err(&tx.signature(), err))
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_mempool/src/mempool_flow_tests.rs (L340-343)
```rust
    // Assert: Mempool state still contains the address, even though the transaction was committed.
    // Note that in the future, the Mempool's state may be periodically cleared from records of old
    // committed transactions. Mirroring this behavior may require a modification of this test.
    assert!(mempool.account_tx_in_pool_or_recent_block(account_address));
```
