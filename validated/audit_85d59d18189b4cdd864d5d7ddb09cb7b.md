Looking at the `skip_stateful_validations` function and the `account_tx_in_pool_or_recent_block` check, I need to trace the exact condition under which `__validate__` (signature verification) is skipped at the gateway level.

### Title
Invoke Transaction with Nonce=1 Bypasses `__validate__` Signature Check via Overly Broad Mempool-Presence Condition — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `skip_stateful_validations` function is intended to skip the `__validate__` entry point only when a `deploy_account` transaction is pending for a new account. However, the guard condition uses `account_tx_in_pool_or_recent_block`, which returns `true` for **any** transaction in the mempool or committed within the last `committed_nonce_retention_block_count` blocks — not exclusively a `deploy_account`. This means an attacker who controls an account with on-chain nonce=0 (e.g., deployed via L1→L2 message or genesis) can first submit a valid nonce=0 invoke to seed the mempool, then submit a nonce=1 invoke with an **invalid or arbitrary signature**, which is admitted to the mempool without running `__validate__`.

---

### Finding Description

In `crates/apollo_gateway/src/stateful_transaction_validator.rs`, the function `skip_stateful_validations` decides whether to skip the blockifier-level `__validate__` call:

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

The guard `account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

`state.contains_account` returns `true` if the address appears in either `staged` (provisionally incremented during block building) or `committed` (finalized nonces from the last `committed_nonce_retention_block_count` = 100 blocks):

```rust
fn contains_account(&self, address: ContractAddress) -> bool {
    self.staged.contains_key(&address) || self.committed.contains_key(&address)
}
```

<cite repo="Camomtat/sequencer--006" path="crates/apollo_mempool/src

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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```
