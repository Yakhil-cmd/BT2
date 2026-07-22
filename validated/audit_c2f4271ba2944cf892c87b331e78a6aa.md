### Title
`skip_stateful_validations` Bypasses `__validate__` for Invoke Transactions When Any (Non-Deploy-Account) Transaction Exists in Mempool - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

`skip_stateful_validations` is intended to skip the `__validate__` entry-point call for an invoke transaction with nonce=1 only when a `deploy_account` transaction for the same address is pending in the mempool (UX feature: deploy + invoke submitted together). However, the mempool query it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** transaction type from that address, not just `deploy_account`. This means an already-deployed account that has a pending nonce=0 invoke in the mempool will cause the gateway to skip `__validate__` for a subsequent nonce=1 invoke, allowing a transaction with an invalid/arbitrary signature to be admitted to the mempool without account-contract validation.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` fires when three conditions are simultaneously true:

1. The incoming transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (on-chain state).

When all three hold, it calls `account_tx_in_pool_or_recent_block(sender_address)` and, if that returns `true`, returns `true` (skip `__validate__`). [1](#0-0) 

The code comment explicitly acknowledges the assumption:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

The second branch of that disjunction is the flaw. A nonce=0 invoke that passed validation proves the account is **already deployed** — not that a `deploy_account` is pending. In that case, `__validate__` must not be skipped.

`account_tx_in_pool_or_recent_block` is type-blind: [2](#0-1) 

It checks `state.contains_account` (any committed nonce) and `tx_pool.contains_account` (any pooled transaction), with no filter on transaction type. [3](#0-2) 

**Attack path:**

1. Account `A` is deployed (class hash set, on-chain nonce = 0).
2. `A`'s owner submits `invoke_tx_1` (nonce=0, valid signature). The gateway calls `__validate__` normally; it passes. `invoke_tx_1` enters the mempool.
3. An attacker (who does **not** know `A`'s private key) submits `invoke_tx_2` (nonce=1, **invalid/arbitrary signature**, sender=`A`).
4. Gateway stateful path: `account_nonce = 0`, `tx.nonce() = 1`, `account_tx_in_pool_or_recent_block(A) = true` (because of `invoke_tx_1`).
5. `skip_stateful_validations` returns `true`; `run_validate_entry_point` is called with `skip_validate=true` — the account's `__validate__` entry point is **never invoked**.
6. `invoke_tx_2` with an invalid signature is admitted to the mempool.

The batcher will later call `__validate__` during execution (with `execution_flags.validate = true`), causing `invoke_tx_2` to fail and be discarded. However, the gateway's admission invariant — that every accepted invoke transaction has passed its account's `__validate__` — is broken.

### Impact Explanation

The gateway unconditionally admits invoke transactions with invalid signatures whenever the sender's address has any pending transaction in the mempool. This violates the **High** impact criterion: "Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing." An attacker can continuously inject invalid-signature transactions for any account that has a live nonce=0 pending transaction, consuming mempool capacity and batcher execution cycles without paying fees (since `__validate__` failure at execution time causes full state rollback including nonce and fee).

### Likelihood Explanation

Any account with a pending nonce=0 transaction is vulnerable. This is a common state during normal operation (e.g., a user's first-ever transaction). The attacker needs only to observe the mempool (public) and submit a crafted nonce=1 invoke. No private key knowledge is required. The condition is easy to trigger and repeatable.

### Recommendation

Replace the type-blind `account_tx_in_pool_or_recent_block` check with a query that specifically verifies a `deploy_account` transaction is pending for the sender address. Either:

- Add a dedicated `has_pending_deploy_account(address)` method to the mempool that inspects the transaction type in the pool, or
- Store the `deploy_account` transaction hash alongside the account entry and verify it matches before skipping `__validate__`.

The current comment's reasoning ("transactions with future nonces that passed validations") is incorrect: a nonce=0 invoke passing validation proves the account is deployed, which is precisely the case where `__validate__` must **not** be skipped.

### Proof of Concept

```
1. Deploy account A (class_hash set, on-chain nonce = 0).
2. Submit invoke_tx_1: sender=A, nonce=0, valid_signature, calldata=[]
   → Gateway: account_nonce=0, tx_nonce=0 → skip_stateful_validations returns false
   → __validate__ called → passes → tx admitted to mempool.
3. Submit invoke_tx_2: sender=A, nonce=1, signature=[0xdead, 0xbeef] (garbage), calldata=[]
   → Gateway stateful path:
       account_nonce = get_nonce_from_state(A) = 0
       tx.nonce() = 1
       account_tx_in_pool_or_recent_block(A) = true  ← invoke_tx_1 is in pool
       skip_stateful_validations returns true
   → run_validate_entry_point(skip_validate=true) → __validate__ NOT called
   → invoke_tx_2 admitted to mempool with invalid signature.
4. Batcher retrieves invoke_tx_2, calls __validate__ → signature check fails → tx rejected.
   Mempool accepted an invalid transaction; admission invariant violated.
``` [4](#0-3) [2](#0-1) [5](#0-4)

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

**File:** crates/apollo_mempool/src/mempool.rs (L105-113)
```rust
    /// Returns the most updated Nonce (including staged) for the address. If no value is found for
    /// address, incoming_account_nonce is returned.
    fn resolve_nonce(&self, address: ContractAddress, incoming_account_nonce: Nonce) -> Nonce {
        self.staged
            .get(&address)
            .or_else(|| self.committed.get(&address))
            .copied()
            .unwrap_or(incoming_account_nonce)
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
