### Title
Signature Verification Bypass via `skip_stateful_validations` Allows Unauthorized Invoke Admission — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator is designed to improve UX for users sending `deploy_account` + `invoke` simultaneously. It skips the `__validate__` entry point (signature verification) for an invoke with nonce=1 when the account nonce is 0 and `account_tx_in_pool_or_recent_block(sender_address)` returns `true`. The critical flaw is that `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction from that address in the mempool — not specifically a `deploy_account`. An unprivileged attacker who observes a victim's `deploy_account` in the mempool can submit an invoke with nonce=1 from the victim's address with arbitrary calldata and a fake/empty signature, and the gateway will accept it without any signature check.

---

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` lines 429–461:

```rust
async fn skip_stateful_validations(...) -> ... {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())  // ← any tx, not deploy_account
                .await
                ...
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When this returns `true`, `run_validate_entry_point` is called with `validate: false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

The `__validate__` entry point — which is the account contract's signature verification — is entirely skipped.

The mempool's `account_tx_in_pool_or_recent_block` checks:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

And `MempoolState::contains_account`:

```rust
fn contains_account(&self, address: ContractAddress) -> bool {
    self.staged.contains_key(&address) || self.committed.contains_key(&address)
}
``` [4](#0-3) 

Neither check verifies that the transaction in the pool is a `deploy_account`. Any transaction type from that address satisfies the condition.

The code comment itself acknowledges the ambiguity:

> "It is sufficient to check if the account exists in the mempool since it means that **either it has a deploy_account transaction or transactions with future nonces that passed validations**." [5](#0-4) 

The "transactions with future nonces that passed validations" branch is exactly the attacker's entry point: the attacker's own invoke(nonce=1) with a fake signature can pass all prior checks (nonce range, resource bounds, mempool duplicate check) and then receive `skip_validate=true` because Alice's `deploy_account` is already in the pool.

The full pre-validation sequence in `run_pre_validation_checks` is:

1. `validate_state_preconditions` — checks nonce range and resource bounds (no signature check)
2. `validate_by_mempool` — checks for duplicate tx_hash and nonce ordering (no signature check)
3. `skip_stateful_validations` — returns `true` if `account_tx_in_pool_or_recent_block` is true
4. `run_validate_entry_point` — skips `__validate__` when `skip_validate=true` [6](#0-5) 

---

### Impact Explanation

**Broken invariant**: The gateway must only admit transactions whose signatures are valid (or whose `__validate__` entry point passes). This invariant is violated for any invoke with nonce=1 targeting an address with a pending `deploy_account`.

**Concrete effects**:

1. **Gateway/mempool admission accepts invalid transactions** — matches "High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing." The attacker's invoke with a fake signature is stored in the mempool.

2. **Legitimate user's invoke is blocked** — once the attacker's invoke(nonce=1) occupies the nonce slot, Alice's invoke(nonce=1) is rejected with `DuplicateNonce` by `validate_incoming_tx`. Alice cannot proceed without fee escalation.

3. **Potential unauthorized execution** — for account contracts that have a permissive or absent `__validate__`

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-312)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
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
