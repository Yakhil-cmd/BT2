### Title
Unauthenticated Invoke Admission via Overly-Broad `skip_stateful_validations` Check — (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary
The `skip_stateful_validations` function bypasses the `__validate__` entry-point (account signature check) for any invoke transaction with nonce=1 submitted to an address whose on-chain nonce is 0, whenever `account_tx_in_pool_or_recent_block` returns `true`. Because that predicate is not restricted to deploy-account transactions, an unprivileged attacker who observes a victim's pending deploy-account in the mempool can immediately submit a crafted invoke with nonce=1 and an arbitrary/invalid signature for the same address, and the gateway will admit it without ever calling `__validate__`.

### Finding Description

`skip_stateful_validations` (lines 429–461) implements the deploy-account + invoke UX shortcut:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...;
}
``` [1](#0-0) 

When it returns `true`, `run_validate_entry_point` is called with `skip_validate = true`, which sets `execution_flags.validate = false` and skips the `__validate__` call entirely:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

The predicate `account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L434-457)
```rust
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
```
