### Title
`skip_stateful_validations` Admits Forged Invoke Transactions for Undeployed Accounts Without Signature Verification - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The gateway's UX-convenience feature for the `deploy_account + invoke` flow skips the blockifier `__validate__` entrypoint call for any Invoke transaction with nonce=1 targeting an address that has *any* transaction in the mempool pool. Because the check is not restricted to deploy-account transactions, an unprivileged attacker can submit a forged Invoke (nonce=1) for a victim's undeployed address and have it admitted to the mempool without signature verification, occupying the victim's nonce=1 slot.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` returns `true` (skip `__validate__`) when three conditions hold simultaneously:

1. The incoming transaction is an `Invoke` with `nonce == 1`.
2. The on-chain account nonce is `0` (account not yet deployed).
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [1](#0-0) 

When `skip_validate` is `true`, `run_validate_entry_point` constructs an `AccountTransaction` with `execution_flags.validate = false`, so the blockifier never calls the account's `__validate__` entrypoint: [2](#0-1) 

The code comment justifies the check as: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* [3](#0-2) 

`account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [4](#0-3) 

`tx_pool.contains_account` returns `true` for **any** transaction type in the pool for that address — not specifically a `DeployAccount` transaction: [5](#0-4) 

`MempoolState.contains_account` returns `true` if the address appears in `staged` or `committed` maps, which are populated by any committed transaction, not only deploy-account transactions: [6](#0-5) 

The reasoning in the comment is therefore incorrect: the presence of *any* transaction for an address in the pool does not imply a deploy-account transaction exists. An attacker can exploit this by observing that a victim's deploy-account is in the pool and then submitting a forged Invoke (nonce=1) for the victim's address. The gateway will skip `__validate__` and admit the forged transaction.

### Impact Explanation

An unprivileged attacker can inject a cryptographically invalid (forged-signature) Invoke transaction into the mempool for any undeployed account that currently has a deploy-account transaction pending. The forged transaction occupies the victim's nonce=1 slot. The victim's own legitimate Invoke with nonce=1 is then rejected with `DuplicateNonce` unless the victim pays a higher fee to trigger fee escalation and replace the forged entry. This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

The attack requires only that the victim's deploy-account transaction is visible in the mempool (which is observable). No privileged access, special keys, or prior relationship with the victim is needed. The attacker only needs to craft an Invoke transaction with an arbitrary signature targeting the victim's address with nonce=1 and submit it to the gateway. The condition `tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO)` is trivially satisfiable for any undeployed account in the deploy+invoke UX flow.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **deploy-account** transaction exists for the sender address in the mempool. Add a dedicated mempool API such as `deploy_account_tx_in_pool(address) -> bool` that inspects the transaction type, and use that in `skip_stateful_validations`. This preserves the UX benefit while closing the forgery window.

### Proof of Concept

1. Alice submits `DeployAccount` for address `A` (nonce=0). It enters the mempool pool.
2. Eve calls the gateway `add_tx` with an `Invoke` transaction: `sender_address=A`, `nonce=1`, `signature=[0xdeadbeef, ...]` (arbitrary bytes).
3. Gateway path:
   - `validate_nonce`: `0 <= 1 <= max_allowed_nonce_gap` → passes.
   - `validate_by_mempool`: no duplicate nonce=1 for `A` → passes.
   - `skip_stateful_validations`: `nonce==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(A)` → `tx_pool.contains_account(A)` is `true` (Alice's deploy-account is there) → returns `true`.
   - `run_validate_entry_point` called with `validate=false` → `__validate__` never invoked.
4. Eve's forged Invoke is admitted to the mempool at `(A, nonce=1)`.
5. Alice now submits her own legitimate Invoke with nonce=1. The mempool returns `DuplicateNonce` unless Alice pays a higher fee to escalate and replace Eve's entry. [7](#0-6) [4](#0-3)

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

**File:** crates/apollo_mempool/src/transaction_pool.rs (L201-203)
```rust
    pub fn contains_account(&self, address: ContractAddress) -> bool {
        self.txs_by_account.contains(address)
    }
```
