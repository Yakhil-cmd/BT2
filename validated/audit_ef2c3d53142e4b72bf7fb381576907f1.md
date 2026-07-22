### Title
Gateway admits invoke transactions with unverified signatures via overly broad `skip_stateful_validations` bypass — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the Apollo gateway's stateful validator is designed to skip the `__validate__` entry point (signature verification) for invoke transactions with nonce=1 when the account is not yet deployed (on-chain nonce=0) and a `deploy_account` is pending in the mempool. However, the mempool check used to authorize this skip — `account_tx_in_pool_or_recent_block` — does not verify that the pending transaction is specifically a `deploy_account`. It returns `true` for **any** transaction from that address in the pool. This allows an attacker to submit a `deploy_account` alongside an invoke transaction carrying an **invalid or arbitrary signature**, and the invoke will be admitted to the mempool without any signature verification.

---

### Finding Description

In `skip_stateful_validations` (lines 429–461 of `stateful_transaction_validator.rs`), the gateway skips the blockifier `__validate__` call when all four conditions hold:

1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)` (nonce is exactly 1).
3. `account_nonce == Nonce(Felt::ZERO)` (on-chain nonce is 0, account not yet deployed).
4. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [1](#0-0) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [2](#0-1) 

This causes `validate_tx` in the blockifier to return `Ok(None)` immediately without executing `__validate__`: [3](#0-2) 

The code comment in `skip_stateful_validations` claims:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

This claim is incorrect. `account_tx_in_pool_or_recent_block` returns `true` if **any** transaction from the address is in the pool: [4](#0-3) 

It does not distinguish between a `deploy_account` and any other transaction type. The function is not type-aware.

**Attack path:**

1. Attacker controls an address with no on-chain deployment (nonce=0).
2. Attacker submits a valid `deploy_account` transaction (nonce=0). This is fully executed by `StatefulValidator::perform_validations` (which calls `self.execute(tx)` for `DeployAccount`), so it passes all checks and enters the mempool. [5](#0-4) 

3. `account_tx_in_pool_or_recent_block` now returns `true` for the attacker's address.
4. Attacker submits an invoke with nonce=1 carrying an **invalid/arbitrary signature**.
5. In `run_pre_validation_checks`: `validate_state_preconditions` passes (nonce 1 is within `max_allowed_nonce_gap` of 0), `validate_by_mempool` passes (only checks nonce ranges, not signatures). [6](#0-5) 

6. `skip_stateful_validations` returns `true` — all four conditions are satisfied.
7. `run_validate_entry_point` is called with `skip_validate=true`, so `__validate__` is never invoked.
8. The invoke with an invalid signature is admitted to the mempool.

---

### Impact Explanation

The gateway's core admission invariant — "every admitted invoke transaction has passed `__validate__` (signature verification)" — is broken. An attacker can inject invoke transactions with arbitrary/invalid signatures into the mempool. These transactions will eventually revert at batcher execution time (when `__validate__` runs with the deployed account), but they occupy mempool slots, waste sequencer execution resources, and violate the security boundary that the gateway is supposed to enforce. This matches: **High. Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

---

### Likelihood Explanation

The trigger requires only that the attacker control an address with on-chain nonce=0 and submit a valid `deploy_account` first. This is a low-barrier, unprivileged operation available to any network participant. The `max_allowed_nonce_gap` configuration (which must be ≥1 to allow nonce=1 when account_nonce=0) is a standard operational setting.

---

### Recommendation

In `skip_stateful_validations`, replace the generic `account_tx_in_pool_or_recent_block` check with a type-specific check that confirms a `deploy_account` transaction (not just any transaction) is pending for the sender address. This requires either:

- A new mempool API `deploy_account_tx_in_pool(address) -> bool` that inspects the transaction type, or
- Passing the `deploy_account` transaction hash explicitly (as the `native_blockifier` path already does via `deploy_account_tx_hash: Option<TransactionHash>` in `PyValidator::should_run_stateful_validations`). [7](#0-6) 

The `native_blockifier` path correctly requires an explicit `deploy_account_tx_hash` to authorize the skip. The Apollo gateway path should adopt the same discipline.

---

### Proof of Concept

```
1. Attacker generates a fresh keypair → address A (no on-chain state, nonce=0).

2. Attacker submits DeployAccount(nonce=0, valid_signature) for address A.
   → StatefulValidator::perform_validations fully executes it (constructor runs).
   → deploy_account enters the mempool.
   → account_tx_in_pool_or_recent_block(A) == true.

3. Attacker submits Invoke(nonce=1, sender=A, signature=[0x0, 0x0, ...]) — invalid signature.
   → validate_state_preconditions: nonce=1 ≥ account_nonce=0, within max_allowed_nonce_gap → PASS.
   → validate_by_mempool: nonce range check only → PASS.
   → skip_stateful_validations:
       tx.nonce()==1 ✓, account_nonce==0 ✓, account_tx_in_pool_or_recent_block(A)==true ✓
       → returns true (skip __validate__).
   → run_validate_entry_point(skip_validate=true):
       execution_flags.validate = false → __validate__ NOT called.
   → Invoke with invalid signature admitted to mempool. ✓

4. Batcher later processes both transactions:
   - DeployAccount executes → account A deployed, nonce becomes 1.
   - Invoke(nonce=1) runs __validate__ → FAILS (invalid signature) → reverts.
   → Invalid transaction was in the mempool; gateway admission invariant violated.
```

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L74-75)
```rust
        match tx.tx {
            ApiTransaction::DeployAccount(_) | ApiTransaction::Declare(_) => self.execute(tx),
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
