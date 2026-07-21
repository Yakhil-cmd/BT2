### Title
Gateway `skip_stateful_validations` Bypasses `__validate__` Signature Check for Pre-Deployed Accounts with Nonce=0 — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function is designed to skip the `__validate__` entry-point call (which performs signature verification) for an invoke transaction with nonce=1 when the account's on-chain nonce is 0 and the account has any transaction in the mempool. The intent is to improve UX for the simultaneous `deploy_account + invoke` flow. However, the guard `account_tx_in_pool_or_recent_block` is too broad: it returns `true` for **any** account that has any transaction in the pool, not only accounts whose `deploy_account` is pending. A pre-deployed account (deployed via the `deploy` syscall or genesis) with on-chain nonce=0 can exploit this to have its nonce=1 invoke transaction admitted to the mempool without any signature verification.

---

### Finding Description

The relevant code path is:

**`extract_state_nonce_and_run_validations`** calls `run_pre_validation_checks`, which calls `skip_stateful_validations`:

```
extract_state_nonce_and_run_validations
  └─ run_pre_validation_checks
       ├─ validate_state_preconditions  (nonce range, resource bounds)
       ├─ validate_by_mempool           (duplicate/nonce-too-old check only)
       └─ skip_stateful_validations     ← decides whether __validate__ runs
```

`skip_stateful_validations` at lines 429–460:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
}
``` [1](#0-0) 

When this returns `true`, `run_validate_entry_point` is called with `skip_validate = true`, which sets `validate: false` in `ExecutionFlags`, causing `validate_tx` to return `Ok(None)` immediately without calling `__validate__`: [2](#0-1) 

The `account_tx_in_pool_or_recent_block` implementation:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

`MempoolState::contains_account` returns `true` if the address appears in either the `staged` or `committed` maps — populated by **any** transaction type, not exclusively `deploy_account`: [4](#0-3) 

The developer comment at line 441–443 states:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

This reasoning is incorrect for pre-deployed accounts (deployed via `deploy` syscall or genesis) with on-chain nonce=0. Such an account **does** have contract code and a working `__validate__`, but having a nonce=0 invoke in the pool does not imply that a nonce=1 invoke has been validated.

**Attack steps:**

1. Attacker controls a pre-deployed account `A` (deployed via `deploy` syscall, on-chain nonce=0, implements account interface).
2. Attacker submits a valid invoke with nonce=0 for account `A`. This passes `validate_nonce` (`0 ≤ 0 ≤ max_allowed_nonce_gap`) and `__validate__` (account exists, signature valid). The transaction enters the mempool.
3. Attacker submits an invoke with nonce=1 for account `A` carrying an **arbitrary/invalid signature**.
   - `validate_nonce`: `0 ≤ 1 ≤ max_allowed_nonce_gap` → passes (requires `max_allowed_nonce_gap ≥ 1`, which is required for the deploy_account+invoke UX feature to work at all).
   - `validate_by_mempool`: no duplicate, nonce not too old → passes.
   - `skip_stateful_validations`: `tx.nonce()==1 && account_nonce==0 && account_in_pool==true` → returns `true`.
   - `run_validate_entry_point`: `skip_validate=true` → `__validate__` is **not called**.
4. The nonce=1 transaction with an invalid signature is admitted to the mempool. [5](#0-4) 

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An attacker can inject invoke transactions with arbitrary/invalid signatures into the mempool, bypassing the gateway's only signature-verification step (`__validate__`). These transactions will fail during batcher execution (the blockifier runs `__validate__` with `strict_nonce_check=true`), but they consume mempool capacity and batcher resources. Because the batcher rejects transactions whose `__validate__` fails without charging fees, the attacker bears no economic cost for the invalid nonce=1 transactions beyond the cost of the initial valid nonce=0 transaction.

---

### Likelihood Explanation

**Low-Medium.** The attacker must control a pre-deployed account (deployed via `deploy` syscall or genesis) with on-chain nonce=0 that implements the account interface. This is an uncommon but entirely valid Starknet pattern. The `max_allowed_nonce_gap` must be ≥ 1, which is a prerequisite for the deploy_account+invoke UX feature itself, so it is always satisfied in production.

---

### Recommendation

Replace the overly broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** exists for the sender address in the pool or a recent block. The mempool should expose a dedicated query such as `deploy_account_tx_in_pool_or_recent_block(address)` that only returns `true` when the pending or recently committed transaction for that address is of type `DeployAccount`.

Alternatively, add a type check inside `skip_stateful_validations` by querying the mempool for the specific transaction type associated with the account.

---

### Proof of Concept

```
// Pre-condition: account A is deployed via `deploy` syscall, on-chain nonce = 0.
// max_allowed_nonce_gap >= 1 (required for deploy_account+invoke UX).

// Step 1: Submit valid invoke, nonce=0, valid signature.
//   → passes validate_nonce (0 ≤ 0 ≤ gap)
//   → passes __validate__ (account exists, sig valid)
//   → enters mempool; account_tx_in_pool_or_recent_block(A) now returns true

// Step 2: Submit invoke, nonce=1, INVALID/ARBITRARY signature.
//   → passes validate_nonce (0 ≤ 1 ≤ gap)
//   → passes validate_by_mempool (no duplicate, nonce not too old)
//   → skip_stateful_validations:
//       tx.nonce()==1 ✓  account_nonce==0 ✓  account_in_pool==true ✓
//       → returns true (skip __validate__)
//   → run_validate_entry_point(skip_validate=true):
//       ExecutionFlags { validate: false, ... }
//       → validate_tx returns Ok(None) immediately
//   → transaction admitted to mempool WITHOUT signature verification

// Result: nonce=1 invoke with invalid signature is in the mempool.
// Batcher will reject it during execution (no fee charged to attacker).
``` [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L158-179)
```rust
    async fn extract_state_nonce_and_run_validations(
        &mut self,
        executable_tx: &ExecutableTransaction,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<Nonce> {
        let account_nonce =
            self.get_nonce_from_state(executable_tx.contract_address()).await.map_err(|e| {
                // TODO(noamsp): Fix this. Need to map the errors better.
                StarknetError::internal_with_signature_logging(
                    format!(
                        "Failed to get nonce for sender address {}",
                        executable_tx.contract_address()
                    ),
                    &executable_tx.signature(),
                    e,
                )
            })?;
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-314)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-460)
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L992-1001)
```rust
impl ValidatableTransaction for AccountTransaction {
    fn validate_tx(
        &self,
        state: &mut dyn State,
        tx_context: Arc<TransactionContext>,
        remaining_gas: &mut GasCounter,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        if !self.execution_flags.validate {
            return Ok(None);
        }
```
