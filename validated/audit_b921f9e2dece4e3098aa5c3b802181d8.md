### Title
Gateway `skip_stateful_validations` accepts any mempool transaction as proof of pending deploy_account, enabling `__validate__` bypass for nonce-1 invokes — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function is designed to skip the `__validate__` entry-point check for an invoke transaction with nonce=1 only when a `deploy_account` is pending in the mempool (UX feature: send deploy+invoke simultaneously). The guard it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** transaction from the sender address, not exclusively a `deploy_account`. An attacker who controls an account that already exists on-chain with nonce=0 can first submit a valid nonce=0 invoke (which passes `__validate__`), then submit a nonce=1 invoke with an **invalid signature**. The second transaction satisfies the skip condition and is admitted to the mempool without `__validate__` being called at the gateway.

---

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` fires when three conditions are simultaneously true:

```
tx is Invoke  AND  tx.nonce() == 1  AND  account_nonce == 0
```

and `account_tx_in_pool_or_recent_block(sender)` returns `true`. [1](#0-0) 

`account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

`MempoolState::contains_account` returns `true` if the address appears in either the `staged` or `committed` maps — populated by **any** transaction type, not only `deploy_account`. [3](#0-2) 

`TransactionPool::contains_account` similarly returns `true` for any transaction in the pool from that address. [4](#0-3) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`, so `StatefulValidator::perform_validations` returns `Ok(())` for the invoke without ever calling `__validate__`: [5](#0-4) [6](#0-5) 

The code comment acknowledges the broader check but incorrectly treats it as safe:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction **or transactions with future nonces that passed validations**." [7](#0-6) 

The flaw: a nonce=0 invoke that passed `__validate__` proves the account's `__validate__` accepted **that specific transaction's signature**. It says nothing about whether a nonce=1 invoke with a different (or zero) signature would pass `__validate__`. Each transaction carries its own signature, and `__validate__` verifies the signature of the specific transaction being submitted.

**Attack path:**

1. Account `A` exists on-chain with nonce=0 (deployed via `deploy` syscall from another contract; attacker holds the private key).
2. Attacker submits `Invoke(sender=A, nonce=0, valid_signature)` → gateway calls `__validate__`, it passes, transaction enters the mempool. `account_tx_in_pool_or_recent_block(A)` now returns `true`.
3. Attacker submits `Invoke(sender=A, nonce=1, signature=[0,0,...])` (invalid/zero signature).
   - `validate_nonce`: account_nonce=0, tx_nonce=1, within `max_allowed_nonce_gap` → passes.
   - `validate_by_mempool`: nonce=1 ≥ resolved nonce=0 → passes.
   - `skip_stateful_validations`: nonce==1, account_nonce==0, `account_tx_in_pool_or_recent_block(A)==true` → returns `true`.
   - `run_validate_entry_point` with `validate=false` → `__validate__` is **never called**.
4. The invalid-signature invoke is admitted to the mempool.
5. During block production the batcher creates a fresh `AccountTransaction` with `validate=true`; `__validate__` is called, fails, and the transaction reverts. The sequencer consumed execution resources for a transaction that was guaranteed to fail.

The nonce validation in `validate_state_preconditions` for invoke transactions only checks the nonce range, not the transaction type: [8](#0-7) 

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

The gateway's stateful validation is the only place where `__validate__` is called before a transaction enters the mempool. By bypassing it, an attacker can inject transactions with invalid signatures (or any other condition that `__validate__` would reject) into the mempool. These transactions are guaranteed to revert during execution, wasting sequencer execution resources. Because the attacker must pay fees for the nonce=0 invoke (which succeeds), this is not a free DoS, but it does allow systematic injection of invalid transactions at the cost of one valid transaction per batch of invalid ones.

---

### Likelihood Explanation

Moderate. The precondition — an account with nonce=0 on-chain that was deployed via `deploy` syscall rather than `deploy_account` — is achievable by any user who can call the `deploy` syscall from an existing account. The attacker needs the private key for the deployed account and must submit one valid nonce=0 invoke first. No privileged access is required.

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** is pending for the sender address. The mempool should expose a dedicated query such as `deploy_account_in_pool(address) -> bool` that inspects the transaction type, rather than returning `true` for any transaction type. Alternatively, the skip condition should be restricted to cases where the account does not exist at all in the state (i.e., `get_class_hash_at(sender) == ClassHash::default()`), which is the true invariant the feature is meant to guard.

---

### Proof of Concept

```
// Precondition: account A deployed via deploy syscall, nonce=0 on-chain, attacker holds key.

// Step 1: submit valid nonce-0 invoke → passes __validate__, enters mempool
gateway.add_invoke_tx(InvokeV3 {
    sender_address: A,
    nonce: 0,
    signature: sign(tx_hash_nonce0, attacker_key),  // valid
    calldata: [...],
    ...
});
// account_tx_in_pool_or_recent_block(A) now returns true

// Step 2: submit nonce-1 invoke with INVALID signature
gateway.add_invoke_tx(InvokeV3 {
    sender_address: A,
    nonce: 1,
    signature: [Felt::ZERO, Felt::ZERO],  // invalid
    calldata: [...],
    ...
});
// skip_stateful_validations returns true:
//   tx.nonce() == 1  ✓
//   account_nonce == 0  ✓
//   account_tx_in_pool_or_recent_block(A) == true  ✓  (due to step 1)
// __validate__ is NOT called; transaction is admitted to mempool.

// Step 3: batcher picks up both transactions; nonce-0 executes successfully,
// nonce-1 calls __validate__ → fails → reverts.
// Sequencer wasted execution resources on a transaction that was guaranteed to fail.
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-313)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```
