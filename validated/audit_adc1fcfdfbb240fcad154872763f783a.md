Looking at the `skip_stateful_validations` function and the `account_tx_in_pool_or_recent_block` check, I need to trace whether the "any tx in mempool" check is too broad, analogous to the Vether `addExcluded` authorization bypass.

Let me examine the mempool's `account_tx_in_pool_or_recent_block` implementation and the `contains_account` logic.

---

### Title
Overly Broad `account_tx_in_pool_or_recent_block` Check in `skip_stateful_validations` Allows Any Account to Bypass Gateway Signature Validation for Nonce-1 Invoke Transactions — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`skip_stateful_validations` is designed to skip the `__validate__` entry-point call for an invoke transaction with nonce=1 when the account's deploy_account transaction is still pending in the mempool. However, the guard condition uses `account_tx_in_pool_or_recent_block`, which returns `true` for **any** transaction from the sender address — not exclusively a `DeployAccount` transaction. An attacker with an already-deployed account (on-chain nonce = 0) can first submit a valid invoke with nonce=0 to seed the mempool, then submit a second invoke with nonce=1 carrying an **invalid signature**. The gateway skips `__validate__` for the second transaction and admits it to the mempool.

---

### Finding Description

`skip_stateful_validations` is called inside `run_pre_validation_checks` after `validate_by_mempool` passes:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:407-408
let skip_validate =
    skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
``` [1](#0-0) 

The skip condition fires when:
1. The transaction is `Invoke`
2. `tx.nonce() == Nonce(Felt::ONE)` (nonce = 1)
3. `account_nonce == Nonce(Felt::ZERO)` (on-chain nonce = 0)
4. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`

The mempool implementation of condition 4:

```rust
// crates/apollo_mempool/src/mempool.rs:697-700
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

`contains_account` checks whether **any** transaction from the address is staged, committed, or pooled:

```rust
// crates/apollo_mempool/src/mempool.rs:115-117
fn contains_account(&self, address: ContractAddress) -> bool {
    self.staged.contains_key(&address) || self.committed.contains_key(&address)
}
``` [3](#0-2) 

The code comment in `skip_stateful_validations` acknowledges this:

> *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction **or transactions with future nonces that passed validations**."* [4](#0-3) 

This reasoning is flawed. A nonce=0 invoke transaction passing `__validate__` (with its own signature) does **not** imply that a nonce=1 invoke transaction carries a valid signature. Each transaction has an independent signature over its own hash.

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:311-312
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [5](#0-4) 

The blockifier's `StatefulValidator::perform_validations` then short-circuits before calling `__validate__`:

```rust
// crates/blockifier/src/blockifier/stateful_validator.rs:79-81
if !tx.execution_flags.validate {
    return Ok(());
}
``` [6](#0-5) 

The mempool's `validate_tx` (called via `validate_by_mempool`) only checks for duplicate hashes and nonce ordering — it never inspects the signature:

```rust
// crates/apollo_mempool/src/mempool.rs:402-408
pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
    let tx_reference = (&args).into();
    self.validate_incoming_tx(tx_reference, args.account_nonce)?;
    self.validate_fee_escalation(tx_reference)?;
    Ok(())
}
``` [7](#0-6) 

The stateless validator checks only signature **size**, not validity. Therefore, an attacker-controlled invalid signature of the correct byte length passes every check.

---

### Impact Explanation

An attacker with a deployed account (on-chain nonce = 0) can:

1. Submit a valid invoke T1 with nonce=0 → passes full gateway validation, enters mempool.
2. Submit invoke T2 with nonce=1 carrying an **arbitrary/invalid signature**.
   - `skip_stateful_validations` fires: nonce=1, on-chain nonce=0, `account_tx_in_pool_or_recent_block` = true (T1 is pooled).
   - `__validate__` is skipped entirely.
   - T2 is admitted to the mempool without signature verification.

This matches the allowed impact: **"Mempool/gateway/RPC admission accepts invalid transactions before sequencing."**

The gateway's invariant — *every admitted invoke transaction must have passed its account's `__validate__` entry point* — is broken. The mempool now holds a transaction whose signature was never verified by the account contract.

---

### Likelihood Explanation

- No special privileges required; any account holder with on-chain nonce=0 can trigger this.
- The attacker only needs to pay fees for the valid nonce=0 transaction.
- The condition `tx.nonce() == 1 && account_nonce == 0` is common immediately after account deployment.
- The existing test suite confirms the skip fires for any pooled transaction, not only deploy-account transactions. [8](#0-7) 

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`DeployAccount`** transaction for the sender address is present in the mempool. Add a dedicated mempool query such as `deploy_account_tx_in_pool(sender_address)` that inspects the transaction type, or pass the deploy-account transaction hash (as the `native_blockifier` path already does via `deploy_account_tx_hash`) and verify it is present and is of type `DeployAccount`. [9](#0-8) 

---

### Proof of Concept

```
Precondition: Alice's account is deployed at address A; on-chain nonce = 0.

Step 1 — Seed the mempool:
  Alice submits InvokeV3 T1:
    sender_address = A
    nonce          = 0
    signature      = valid_sig(T1_hash)
  → Gateway runs __validate__ for T1 → passes → T1 enters mempool.
  → mempool.account_tx_in_pool_or_recent_block(A) now returns true.

Step 2 — Submit invalid-signature transaction:
  Alice submits InvokeV3 T2:
    sender_address = A
    nonce          = 1
    signature      = [0xff; 64]   // arbitrary garbage, correct length

  Gateway stateful path:
    account_nonce = get_nonce_from_state(A) = 0
    skip_stateful_validations:
      tx.nonce() == 1  ✓
      account_nonce == 0  ✓
      account_tx_in_pool_or_recent_block(A) == true  ✓  (T1 is pooled)
      → returns true (skip validation)
    run_validate_entry_point(skip_validate=true):
      execution_flags.validate = false
      StatefulValidator::perform_validations → early return, __validate__ never called
  → T2 admitted to mempool with invalid signature.

Result: The mempool contains T2 whose signature was never verified.
```

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

**File:** crates/apollo_mempool/src/mempool.rs (L402-408)
```rust
    pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
        let tx_reference = (&args).into();
        self.validate_incoming_tx(tx_reference, args.account_nonce)?;
        self.validate_fee_escalation(tx_reference)?;

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator_test.rs (L151-157)
```rust
#[rstest]
#[case::should_skip_validation(
    executable_invoke_tx(invoke_tx_args!(nonce: nonce!(1))),
    nonce!(0),
    true,
    false
)]
```

**File:** crates/native_blockifier/src/py_validator.rs (L109-118)
```rust
        let deploy_account_not_processed =
            deploy_account_tx_hash.is_some() && nonce == Nonce(Felt::ZERO);
        let tx_nonce = tx_info.nonce();
        let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;
```
