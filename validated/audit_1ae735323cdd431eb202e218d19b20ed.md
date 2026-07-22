### Title
Signature Validation Bypass via `skip_stateful_validations` Allows Unauthorized Invoke Admission for Undeployed Accounts - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry-point call (which performs signature verification) for any invoke transaction with `nonce == 1` targeting an account whose on-chain nonce is `0`, provided `account_tx_in_pool_or_recent_block` returns `true` for that address. Because `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction type in the pool (not only `DeployAccount`), an unprivileged attacker who observes a victim's `DeployAccount` transaction in the mempool can immediately submit a second invoke transaction for the victim's address with an arbitrary/empty signature and have it admitted by the gateway without any cryptographic authorization check.

### Finding Description

The gateway stateful validation path is:

```
extract_state_nonce_and_run_validations
  → run_pre_validation_checks
      → validate_state_preconditions   (nonce range, resource bounds)
      → validate_by_mempool            (duplicate hash, nonce-too-old)
      → skip_stateful_validations      ← returns true → __validate__ is SKIPPED
  → run_validate_entry_point(skip_validate=true)
      → ExecutionFlags { validate: false, … }
      → StatefulValidator::perform_validations
          → if !tx.execution_flags.validate { return Ok(()); }  ← exits immediately
``` [1](#0-0) 

The skip condition is:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await …;
}
``` [2](#0-1) 

`account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

`contains_account` checks only whether the address appears in the staged/committed maps or the pool — it does **not** verify that the matching transaction is a `DeployAccount`:

```rust
fn contains_account(&self, address: ContractAddress) -> bool {
    self.staged.contains_key(&address) || self.committed.contains_key(&address)
}
``` [4](#0-3) 

When `skip_validate = true`, `run_validate_entry_point` sets `validate: !skip_validate = false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [5](#0-4) 

The blockifier's `StatefulValidator::perform_validations` then returns immediately without calling `__validate__`:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
``` [6](#0-5) 

The mempool's `validate_incoming_tx` only rejects transactions whose nonce is strictly less than the account nonce — it does **not** reject a second transaction with the same `(address, nonce=1

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
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

**File:** crates/apollo_mempool/src/mempool.rs (L115-117)
```rust
    fn contains_account(&self, address: ContractAddress) -> bool {
        self.staged.contains_key(&address) || self.committed.contains_key(&address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```
