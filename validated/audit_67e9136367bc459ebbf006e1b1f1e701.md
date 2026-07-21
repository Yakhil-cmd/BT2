### Title
Gateway Skips `__validate__` Signature Check for Invoke Transactions with Nonce=1 When Any Pending Transaction Exists for the Sender — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`skip_stateful_validations` unconditionally skips the `__validate__` entry-point call (which performs signature verification) for any Invoke transaction with `nonce=1` submitted against an account whose on-chain nonce is `0`, provided `account_tx_in_pool_or_recent_block` returns `true` for the sender address. Because `account_tx_in_pool_or_recent_block` returns `true` whenever **any** transaction from that address is in the pool — not only a `deploy_account` — an attacker who observes a victim's pending `deploy_account` in the mempool can submit a forged Invoke with `nonce=1` from the victim's address carrying an invalid or empty signature, and the gateway will admit it to the mempool without ever calling `__validate__`.

---

### Finding Description

**Trigger path:**

`StatefulTransactionValidator::extract_state_nonce_and_run_validations`
→ `run_pre_validation_checks`
→ `skip_stateful_validations`
→ `run_validate_entry_point` with `validate: false` [1](#0-0) 

The skip condition fires when all three hold:

1. The incoming transaction is `ExecutableTransaction::Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed in committed state).
4. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [2](#0-1) 

When `skip_validate` is `true`, `run_validate_entry_point` constructs `ExecutionFlags { validate: false, … }` and calls `blockifier_validator.validate(account_tx)`. Inside `StatefulValidator::perform_validations`, the branch `if !tx.execution_flags.validate { return Ok(()); }` exits immediately without ever calling `validate_tx` (the `__validate__` entry point). [3](#0-2) [4](#0-3) 

**The flawed guard:**

`account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [5](#0-4) 

`tx_pool.contains_account` returns `true` if **any** transaction from that address is present in the pool — including a `deploy_account` submitted by the legitimate owner. [6](#0-5) 

The code comment claims this is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." This reasoning is correct for the legitimate user's own invoke, but it does not prevent a **third party** from submitting a forged invoke for the same address, because the check is on the sender address alone, not on the identity of the submitter.

**Attack steps:**

1. Victim broadcasts a `deploy_account` for address `A`; it enters the mempool (`tx_pool.contains_account(A)` → `true`). On-chain nonce of `A` is still `0`.
2. Attacker submits `Invoke { sender_address: A, nonce: 1, signature: [] }` (empty or garbage signature).
3. Gateway stateless checks pass (no signature length limit enforced for invoke).
4. `validate_nonce` passes: `0 ≤ 1 ≤ max_allowed_nonce_gap`.
5. `validate_by_mempool` passes: nonce/fee checks only, no signature check.
6. `skip_stateful_validations` returns `true` (conditions 1–4 all satisfied).
7. `run_validate_entry_point` is called with `validate: false`; `__validate__` is never invoked.
8. The forged invoke is admitted to the mempool. [7](#0-6) 

---

### Impact Explanation

The forged invoke occupies the `(A, nonce=1)` slot in the mempool. The victim's legitimate invoke with `nonce=1` is rejected as a duplicate nonce (`MempoolError::DuplicateNonce`) unless the victim pays a higher fee for fee escalation. When the batcher eventually pulls the forged tx and executes it, `new_for_sequencing` sets `validate: true`, `__validate__` is called, the invalid signature causes a non-revertible failure, and the tx is rejected and removed from the mempool — but only after consuming batcher resources and blocking the victim's slot. [8](#0-7) [9](#0-8) 

**Impact category:** High — Mempool/gateway admission accepts an invalid transaction (one whose `__validate__` would fail) before sequencing, and the invalid transaction can block the legitimate nonce=1 slot for any account undergoing deployment.

---

### Likelihood Explanation

The attack requires only that the attacker observe a `deploy_account` transaction in the mempool (or in a recent block via `state.contains_account`). Mempool contents are visible to any node participant. No privileged access, special key material, or on-chain funds are required to submit the forged invoke. The attacker needs only to know the victim's deploying address, which is deterministic from the `deploy_account` transaction itself.

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` guard with a check that specifically verifies a **`deploy_account`** transaction exists for the sender address, not merely any transaction. Alternatively, restrict the skip to cases where the mempool can confirm the pending transaction for the address is of type `DeployAccount`. This preserves the UX intent (allowing deploy+invoke in one shot) while preventing third parties from exploiting the skip for arbitrary addresses.

---

### Proof of Concept

```
// Precondition: victim has submitted deploy_account for address A.
// Mempool state: tx_pool.contains_account(A) == true
// On-chain state: get_nonce(A) == 0

// Attacker submits:
RpcInvokeTransactionV3 {
    sender_address: A,          // victim's address
    nonce: 1,
    signature: [],              // empty / invalid
    calldata: [<arbitrary>],
    resource_bounds: <valid>,
    ...
}

// Gateway flow:
// 1. validate_nonce: 0 <= 1 <= max_allowed_nonce_gap  → OK
// 2. validate_by_mempool: nonce/fee check only         → OK
// 3. skip_stateful_validations:
//      nonce==1 && account_nonce==0 && contains_account(A)==true → returns true
// 4. run_validate_entry_point(skip_validate=true):
//      ExecutionFlags { validate: false }
//      StatefulValidator::perform_validations → early return, __validate__ never called
// 5. Transaction admitted to mempool at slot (A, nonce=1)

// Victim's legitimate invoke(nonce=1) now rejected: DuplicateNonce
// Batcher later rejects attacker's tx (validate=true, __validate__ fails)
// but victim's slot was blocked.
``` [10](#0-9) [5](#0-4) [4](#0-3)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-312)
```rust
    #[sequencer_latency_histogram(GATEWAY_VALIDATE_TX_LATENCY, true)]
    async fn run_validate_entry_point(
        &mut self,
        executable_tx: &ExecutableTransaction,
        skip_validate: bool,
    ) -> StatefulTransactionValidatorResult<()> {
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L426-461)
```rust
/// Check if validation of an invoke transaction should be skipped due to deploy_account not being
/// processed yet. This feature is used to improve UX for users sending deploy_account + invoke at
/// once.
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L147-155)
```rust
    pub fn new_for_sequencing(tx: Transaction) -> Self {
        let execution_flags = ExecutionFlags {
            only_query: false,
            charge_fee: enforce_fee(&tx, false),
            validate: true,
            strict_nonce_check: true,
        };
        AccountTransaction { tx, execution_flags }
    }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
```
