### Title
Gateway Admits Invoke Transactions with Invalid Signatures via `skip_stateful_validations` Bypass - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally bypasses the `__validate__` entry-point call (which performs signature verification) for any invoke transaction with `nonce == 1` whenever the sender address has *any* transaction present in the mempool or a recent block. An unprivileged attacker who observes a victim's pending `deploy_account` transaction can immediately front-run it with an invoke carrying an arbitrary invalid signature, causing the gateway to admit the invalid transaction to the mempool without ever verifying the signature.

### Finding Description

The gateway stateful validation path is:

```
extract_state_nonce_and_run_validations
  → run_pre_validation_checks
      → validate_state_preconditions   (nonce range + resource bounds)
      → validate_by_mempool            (mempool-level nonce dedup)
      → skip_stateful_validations      ← returns true → __validate__ SKIPPED
  → run_validate_entry_point(skip_validate=true)  ← execution_flags.validate = false
``` [1](#0-0) 

`skip_stateful_validations` returns `true` (skip the `__validate__` entry point) when all three conditions hold:

1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet on-chain).
4. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [2](#0-1) 

Condition 4 is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

This check returns `true` if the address has **any** transaction in the pool — it does not verify that the transaction is specifically a `deploy_account`. When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [4](#0-3) 

This means `AccountTransaction::validate_tx` returns `Ok(None)` immediately without calling `__validate__`: [5](#0-4) 

The upstream checks (`validate_state_preconditions` and `validate_by_mempool`) do **not** verify signatures — they only check nonce range and resource bounds: [6](#0-5) 

**Attack path:**

1. Victim submits a valid `deploy_account` for address `A` → admitted to mempool.
2. Attacker observes the mempool, sees `deploy_account` for `A`.
3. Attacker submits `Invoke { sender: A, nonce: 1, signature: [0xdeadbeef] }` (invalid signature).
4. Gateway evaluates:
   - `validate_state_preconditions`: `account_nonce=0`, `tx_nonce=1`, gap=1 ≤ 200 → **passes**.
   - `validate_by_mempool`: nonce=1 is a valid future nonce → **passes**.
   - `skip_stateful_validations`: `tx.nonce()==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(A)==true` → returns `true`.
   - `run_validate_entry_point(skip_validate=true)`: `__validate__` **not called**.
5. Attacker's invalid invoke is **admitted to the mempool**.
6. Victim submits valid `Invoke { sender: A, nonce: 1, signature: <valid> }`.
7. Mempool rejects it: `MempoolError::DuplicateNonce` (nonce=1 already occupied). [7](#0-6) 

### Impact Explanation

The gateway admits an invoke transaction with an invalid (attacker-controlled) signature to the mempool, violating the invariant that all mempool transactions have passed account-level authorization. Concretely:

- **Invalid transaction accepted**: An invoke with a forged signature enters the mempool and occupies the `(address, nonce=1)` slot.
- **Valid transaction rejected**: The victim's correctly-signed invoke for the same `(address, nonce=1)` is rejected as `DuplicateNonce`.
- **Repeated DoS**: The attacker's invalid invoke fails at execution time and is evicted, but the attacker can immediately repeat the attack, permanently blocking the victim's first post-deployment invoke.

This matches: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

The attack requires only:
1. Monitoring the public mempool for `deploy_account` transactions (no privilege required).
2. Submitting an invoke with nonce=1 and any signature before the victim does.

No special access, no privileged role, no cryptographic capability is needed. The mempool is observable by any network participant.

### Recommendation

`skip_stateful_validations` should verify that the account's mempool entry is specifically a `deploy_account` transaction, not just any transaction. The mempool client interface should expose a dedicated query such as `has_pending_deploy_account(address)` that checks `tx_pool` for a `DeployAccount` variant at nonce=0. Alternatively, the skip logic should be removed and replaced with a mechanism that runs `__validate__` against a simulated post-deployment state.

### Proof of Concept

```
# Step 1: Victim submits deploy_account for address A (valid)
POST /gateway/add_transaction
{ "type": "DEPLOY_ACCOUNT", "sender_address": A, "nonce": "0x0", "signature": [<valid>], ... }
→ Accepted, A now in mempool

# Step 2: Attacker submits invoke with nonce=1, invalid signature
POST /gateway/add_transaction
{ "type": "INVOKE", "sender_address": A, "nonce": "0x1", "signature": ["0xdeadbeef"], ... }
→ Gateway: account_nonce=0, tx_nonce=1, account_tx_in_pool_or_recent_block(A)=true
→ skip_stateful_validations returns true → __validate__ NOT called
→ ACCEPTED into mempool (invalid signature never checked)

# Step 3: Victim submits valid invoke with nonce=1
POST /gateway/add_transaction
{ "type": "INVOKE", "sender_address": A, "nonce": "0x1", "signature": [<valid>], ... }
→ Mempool: DuplicateNonce for (A, nonce=1)
→ REJECTED

# Step 4: Attacker's invalid invoke fails at block execution (__validate__ called with validate=true)
# Attacker repeats from Step 2 indefinitely
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L213-221)
```rust
    async fn validate_state_preconditions(
        &self,
        executable_tx: &ExecutableTransaction,
        account_nonce: Nonce,
    ) -> StatefulTransactionValidatorResult<()> {
        self.validate_resource_bounds(executable_tx).await?;
        self.validate_nonce(executable_tx, account_nonce)?;
        Ok(())
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
```
