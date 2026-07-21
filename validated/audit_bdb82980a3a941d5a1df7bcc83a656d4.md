### Title
Gateway `skip_stateful_validations` bypasses `__validate__` for invoke transactions when any account transaction is in the mempool, not just `deploy_account` — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function uses `account_tx_in_pool_or_recent_block` to decide whether to skip the `__validate__` entry point (signature verification) for an invoke transaction with nonce=1 from an account whose on-chain nonce is 0. The check is too broad: it returns `true` for **any** pending transaction in the mempool, not only `deploy_account` transactions. An attacker can exploit this to submit invoke transactions with invalid signatures for any account that has a pending nonce=0 transaction in the mempool.

---

### Finding Description

`skip_stateful_validations` is designed to improve UX for the simultaneous deploy_account + invoke flow: when a user submits both a `deploy_account` and a nonce=1 invoke at the same time, the invoke should be admitted even though the account does not yet exist on-chain. The function skips `__validate__` for invoke transactions with nonce=1 when the account's on-chain nonce is 0 and `account_tx_in_pool_or_recent_block` returns `true`. [1](#0-0) 

The comment in the code states:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

This reasoning is flawed. `account_tx_in_pool_or_recent_block` returns `true` if the account has **any** transaction in the pool or any committed nonce in the recent block history: [2](#0-1) [3](#0-2) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` is called with `skip_validate=true`, which sets `validate=false` in `ExecutionFlags`: [4](#0-3) 

Inside `StatefulValidator::perform_validations`, when `validate=false`, the function returns `Ok(())` immediately after `perform_pre_validation_stage`, without ever calling the `__validate__` entry point: [5](#0-4) 

**Attack scenario:**

1. Account A is deployed (has a `__validate__` entry point), on-chain nonce = 0.
2. Account A submits a valid invoke tx with nonce=0 → admitted to mempool (passes `__validate__` normally).
3. Attacker submits an invoke tx for account A with nonce=1 and an **invalid/arbitrary signature**.
4. Gateway checks: `tx.nonce() == 1` ✓, `account_nonce == 0` ✓.
5. Gateway calls `account_tx_in_pool_or_recent_block(A)` → returns `true` (the nonce=0 tx is in the pool).
6. `skip_validate = true` → `validate = false`.
7. `StatefulValidator::perform_validations` returns `Ok(())` without calling `__validate__`.
8. The invalid transaction is admitted to the mempool without signature verification.

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks nonce ordering (NonceTooOld), not signatures: [6](#0-5) 

The `validate_nonce` check in `validate_state_preconditions` also passes for nonce=1 with account_nonce=0 (1 is within the allowed gap): [7](#0-6) 

No existing guard preserves the invariant that `__validate__` must run for every invoke transaction from an already-deployed account.

---

### Impact Explanation

The gateway admits an invoke transaction with an invalid (attacker-controlled) signature to the mempool. This violates the admission invariant: **"Mempool/gateway/RPC admission accepts invalid transactions before sequencing."** The invalid transaction will fail during blockifier execution when `__validate__` runs, but it has already been admitted, consuming mempool slots and wasting sequencer execution resources. An attacker can use this to flood the mempool with invalid transactions for any account that has a pending nonce=0 transaction, causing DoS and resource exhaustion.

---

### Likelihood Explanation

Any account with a pending nonce=0 invoke transaction in the mempool is vulnerable. An attacker can observe the mempool (via RPC or P2P gossip) for such accounts and immediately submit invalid nonce=1 transactions. No privileged access is required. The condition (`tx_nonce == 1`, `account_nonce == 0`, any tx in pool) is common during normal operation.

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a specific check that verifies a **`deploy_account` transaction** is pending for the account. The mempool should expose a method such as `has_pending_deploy_account(address) -> bool` that inspects the transaction type of the pending transaction, rather than returning `true` for any transaction type. Alternatively, the gateway can inspect the transaction type of the pending nonce=0 transaction before deciding to skip `__validate__`.

---

### Proof of Concept

```
1. Account A: deployed (class_hash != 0, has __validate__), on-chain nonce = 0.

2. Account A owner submits:
     InvokeV3 { sender: A, nonce: 0, signature: valid_sig, ... }
   → Gateway: validate_nonce OK, __validate__ runs, passes → admitted to mempool.

3. Attacker submits:
     InvokeV3 { sender: A, nonce: 1, signature: [0xdeadbeef], ... }
   → Gateway stateful validation:
       account_nonce = get_nonce_from_state(A) = 0
       validate_nonce: 0 <= 1 <= 0+max_gap → OK
       validate_by_mempool: nonce 1 >= 0 → OK
       skip_stateful_validations:
           tx.nonce() == 1 ✓
           account_nonce == 0 ✓
           account_tx_in_pool_or_recent_block(A):
               tx_pool.contains_account(A) = true  ← nonce=0 tx is in pool
           → returns true (skip __validate__)
       run_validate_entry_point(skip_validate=true):
           validate = false
           StatefulValidator::perform_validations:
               perform_pre_validation_stage → OK
               if !tx.execution_flags.validate { return Ok(()); }  ← exits here
   → Invalid tx admitted to mempool without signature check.

4. Batcher picks up the nonce=1 tx and executes it:
   → __validate__ runs → fails (invalid signature) → tx reverts.
   → Sequencer wasted execution resources; mempool slot was consumed.
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L287-296)
```rust
            _ => {
                let max_allowed_nonce =
                    Nonce(account_nonce.0 + Felt::from(self.config.max_allowed_nonce_gap));
                if !(account_nonce <= incoming_tx_nonce && incoming_tx_nonce <= max_allowed_nonce) {
                    return Err(create_error(format!(
                        "Invalid transaction nonce. Expected: {account_nonce} <= nonce <= \
                         {max_allowed_nonce}, got: {incoming_tx_nonce}."
                    )));
                }
            }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-312)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
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

**File:** crates/apollo_mempool/src/mempool.rs (L162-174)
```rust
    fn validate_incoming_tx(
        &self,
        tx_reference: TransactionReference,
        incoming_account_nonce: Nonce,
    ) -> MempoolResult<()> {
        let TransactionReference { address, nonce: tx_nonce, .. } = tx_reference;
        let account_nonce = self.resolve_nonce(address, incoming_account_nonce);
        if tx_nonce < account_nonce {
            return Err(MempoolError::NonceTooOld { address, tx_nonce, account_nonce });
        }

        Ok(())
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```
