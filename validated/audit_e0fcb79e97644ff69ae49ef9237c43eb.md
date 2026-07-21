### Title
Signature Verification Bypass via `skip_stateful_validations` Allows Unsigned Invoke Transactions to Enter Mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`skip_stateful_validations` skips the `__validate__` entry point (the account's signature-verification function) for any invoke transaction with `nonce=1` when `account_tx_in_pool_or_recent_block` returns `true` for the sender. Because that check returns `true` for **any** account that has **any** pending transaction in the mempool — not specifically a deploy-account transaction submitted by the same signer — an unprivileged attacker can submit an invoke transaction with an arbitrary/invalid signature for any account whose deploy-account transaction is currently pending, and the gateway will accept it without ever verifying the signature.

---

### Finding Description

**Invariant broken:** Every transaction admitted to the mempool must have its account signature verified before admission.

**Root cause — `skip_stateful_validations`:** [1](#0-0) 

The function returns `true` (skip validation) when:
1. The transaction is an `Invoke` with `nonce == 1`, and
2. `account_nonce == 0` (account not yet deployed), and
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`.

Condition 3 is satisfied by the presence of **any** transaction for that address in the mempool — it does not distinguish between a deploy-account transaction submitted by the legitimate owner and an unrelated transaction.

**Effect on the validation pipeline:**

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [2](#0-1) 

This propagates into `StatefulValidator::perform_validations`, which short-circuits before calling `__validate__`: [3](#0-2) 

`AccountTransaction::validate_tx` also returns `Ok(None)` immediately when `execution_flags.validate == false`: [4](#0-3) 

The `__validate__` entry point — the only place where the account's signature is cryptographically verified — is never called.

**No other guard catches this.** The stateless validator only checks signature *size*, not validity: [5](#0-4) 

`validate_by_mempool` checks nonce range and fee escalation, not signature: [6](#0-5) 

**`account_tx_in_pool_or_recent_block` is not deploy-account-specific:** [7](#0-6) 

It returns `true` whenever the address appears in the pool or committed-block state — regardless of transaction type.

---

### Impact Explanation

An attacker who observes a pending deploy-account transaction for account A in the mempool can immediately submit an invoke transaction with `nonce=1` for account A carrying an arbitrary or empty signature. The gateway will:

1. Read `account_nonce = 0` from state (account not yet deployed).
2. Pass nonce-range validation (`0 ≤ 1 ≤ max_allowed_nonce_gap`).
3. Pass `validate_by_mempool` (no duplicate hash, no nonce conflict).
4. Call `skip_stateful_validations` → `account_tx_in_pool_or_recent_block(A)` returns `true` → returns `true`.
5. Call `run_validate_entry_point` with `skip_validate=true` → `execution_flags.validate=false` → `__validate__` never called.
6. Accept the transaction into the mempool.

The admitted transaction carries an invalid signature. When the batcher later executes it, `__validate__` is called with `validate=true` and the transaction reverts. However, the gateway has already admitted an invalid transaction — violating the admission invariant — and the transaction occupies mempool and block space.

**Matched impact category:** *High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.*

---

### Likelihood Explanation

The trigger is fully unprivileged and requires only:
- Monitoring the public mempool for deploy-account transactions (observable by any node).
- Submitting a crafted invoke transaction with `nonce=1` for the target address.

No special keys, roles, or privileged access are needed. The window of opportunity is the entire time the deploy-account transaction remains unconfirmed in the mempool.

---

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a type-specific query that confirms a **deploy-account** transaction (not just any transaction) is pending for the sender address. Alternatively, restrict the skip-validate path to cases where the gateway itself accepted the deploy-account transaction in the same request batch, rather than relying on a mempool-wide presence check.

The relevant logic to tighten: [8](#0-7) 

---

### Proof of Concept

```
1. Alice submits DeployAccount(nonce=0, sender=A, valid_sig) → gateway accepts → mempool contains tx for A.

2. Attacker submits Invoke(nonce=1, sender=A, calldata=<arbitrary>, sig=[0x0]) to gateway.

3. Gateway flow:
   a. StatelessTransactionValidator::validate → passes (sig size ≥ 0).
   b. extract_state_nonce_and_run_validations:
      - get_nonce_from_state(A) → Nonce(0)          // account not deployed
      - validate_nonce: 0 ≤ 1 ≤ max_gap → OK
      - validate_by_mempool: no dup hash, nonce OK → OK
      - skip_stateful_validations:
          tx.nonce()==1 && account_nonce==0 → true
          account_tx_in_pool_or_recent_block(A) → true  // Alice's deploy-account is there
          returns true
      - run_validate_entry_point(skip_validate=true):
          execution_flags.validate = false
          StatefulValidator::perform_validations → returns Ok(()) without __validate__
   c. Gateway calls mempool.add_tx → attacker's tx enters mempool.

4. Batcher picks up both transactions:
   - Alice's DeployAccount executes successfully; account A is deployed.
   - Attacker's Invoke executes: __validate__ is called (validate=true), sig=[0x0] fails → tx reverts.
   - Invalid transaction occupied mempool and block space; admission invariant violated.
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L142-150)
```rust
    fn validate_tx_size(&self, tx: &RpcTransaction) -> StatelessTransactionValidatorResult<()> {
        self.validate_tx_extended_calldata_size(tx)?;
        self.validate_tx_signature_size(tx)?;
        if let RpcTransaction::Invoke(invoke_tx) = tx {
            self.validate_proof_size(invoke_tx)?;
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
