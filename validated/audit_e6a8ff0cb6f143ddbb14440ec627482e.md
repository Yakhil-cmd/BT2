### Title
Attacker Bypasses `__validate__` Signature Check to DOS Victim's First Post-Deploy Invoke — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`skip_stateful_validations` skips the account contract's `__validate__` entry point (the only cryptographic signature check) for any invoke transaction with `tx_nonce == 1` and `account_nonce == 0`, provided `account_tx_in_pool_or_recent_block` returns `true`. Because that helper returns `true` for **any** transaction in the pool for the target address — not specifically a `deploy_account` — an unprivileged attacker can submit a forged invoke (nonce=1, arbitrary calldata, garbage signature) for any account whose `deploy_account` is pending in the mempool. The forged transaction is admitted without signature verification, occupies the nonce=1 slot, and blocks the victim's legitimate first invoke.

---

### Finding Description

The gateway stateful validation path is:

```
extract_state_nonce_and_run_validations
  └─ run_pre_validation_checks
       ├─ validate_state_preconditions   (nonce range, resource bounds)
       ├─ validate_by_mempool            (duplicate hash/nonce check only)
       └─ skip_stateful_validations      ← decides whether __validate__ runs
  └─ run_validate_entry_point(skip_validate)
``` [1](#0-0) 

`skip_stateful_validations` returns `true` (skip) when all three conditions hold:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await …;
}
``` [2](#0-1) 

The comment claims this is safe because the pool entry "means that either it has a deploy_account transaction or transactions with future nonces that passed validations." However, `account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

It returns `true` for **any** transaction in the pool for that address — including the victim's own `deploy_account`. There is no type-check that the pooled transaction is actually a `deploy_account`.

When `skip_validate == true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [4](#0-3) 

Inside `StatefulValidator::perform_validations`, when `validate == false` the `__validate__` call is entirely skipped:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
// `__validate__` call.
let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
``` [5](#0-4) 

`validate_by_mempool` (called before `skip_stateful_validations`) only checks for duplicate transaction hash and nonce-range consistency; it does **not** verify the cryptographic signature. [6](#0-5) 

---

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts an invalid (unsigned) transaction before sequencing.**

The attacker's forged invoke (nonce=1, garbage signature) is admitted to the mempool. When the victim subsequently submits their legitimate invoke (nonce=1), the mempool rejects it with `DuplicateNonce`. The victim's first post-deploy-account transaction is permanently blocked until the attacker's transaction either expires (TTL) or is replaced via fee escalation. During that window the victim's account is effectively frozen at nonce=1.

The attacker's transaction will eventually fail during batcher execution (the blockifier calls `__validate__` with `validate=true` during actual execution), but the DOS window is the entire mempool TTL.

---

### Likelihood Explanation

**Likelihood: High.**

- Requires no special privilege — any unprivileged address can submit an `InvokeV3` transaction.
- The trigger condition (pending `deploy_account` in mempool, account nonce = 0 on-chain) is the normal state for every new Starknet account during the deploy+invoke UX flow the feature was designed to support.
- The attacker only needs to observe the mempool for a `deploy_account` transaction (public information) and immediately submit a forged invoke for the same sender address.
- No funds are required at the attacker's address; the forged transaction will fail at execution, but the DOS is already achieved.

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a type-specific check that confirms a **`deploy_account`** transaction (not just any transaction) is pending for the address. For example, expose a `deploy_account_in_pool(address)` query from the mempool and use it in `skip_stateful_validations`. This preserves the UX intent (allow the paired invoke to skip validation when a deploy_account is genuinely pending) while closing the forgery window.

```rust
// Instead of:
mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address()).await

// Use:
mempool_client.deploy_account_in_pool(tx.sender_address()).await
```

---

### Proof of Concept

1. Alice submits `deploy_account` (nonce=0) for address `A`. It enters the mempool. On-chain nonce for `A` is still 0.

2. Attacker observes the mempool and submits `InvokeV3` for address `A`, nonce=1, arbitrary calldata, garbage `signature = [0x1, 0x2]`.

3. Gateway stateful validation:
   - `validate_nonce`: `account_nonce=0`, `tx_nonce=1`, within `max_allowed_nonce_gap` → **passes**.
   - `validate_by_mempool`: no existing tx with hash or nonce=1 for `A` → **passes**.
   - `skip_stateful_validations`: `tx_nonce==1 && account_nonce==0 && account_tx_in_pool_or_recent_block(A)==true` (Alice's deploy_account is in pool) → returns **`true`**.
   - `run_validate_entry_point(skip_validate=true)`: `execution_flags.validate=false` → `__validate__` **not called**.

4. Attacker's forged invoke is admitted to the mempool at `(A, nonce=1)`.

5. Alice submits her legitimate invoke (nonce=1, valid signature). `validate_by_mempool` returns `MempoolError::DuplicateNonce` → **Alice's transaction is rejected**.

6. Alice's account is DOS'd at nonce=1 for the duration of the attacker's transaction TTL.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L310-312)
```rust
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L413-424)
```rust
/// Perform transaction validation by the mempool.
async fn validate_by_mempool(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<()> {
    let validation_args = ValidationArgs::new(tx, account_nonce);
    mempool_client
        .validate_tx(validation_args)
        .await
        .map_err(|err| mempool_client_err_to_deprecated_gw_err(&tx.signature(), err))
}
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-84)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
```
