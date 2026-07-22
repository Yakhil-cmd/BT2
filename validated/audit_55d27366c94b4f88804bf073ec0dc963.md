### Title
`skip_stateful_validations` Bypasses `__validate__` Signature Check for Nonce-1 Invoke Transactions When Any Prior Transaction Exists in Mempool - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function is designed to skip the `__validate__` entry-point call for an invoke transaction with `tx_nonce == 1` and `account_nonce == 0`, to support the UX pattern of sending `deploy_account + invoke` simultaneously. The guard it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** account that has **any** transaction in the mempool, not only accounts that have a pending `deploy_account`. An attacker with a deployed account at nonce 0 can first submit a valid nonce-0 invoke (which populates the mempool entry), then submit a nonce-1 invoke carrying an **invalid signature**. The second transaction passes all stateless and stateful pre-checks, `skip_stateful_validations` returns `true`, and `run_validate_entry_point` is called with `validate: false`, so the account's `__validate__` entry point — the only place where the signature is cryptographically verified — is never executed. The transaction is admitted to the mempool with an invalid signature.

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

It returns `true` for **any** account that has **any** transaction in the pool — not specifically a `deploy_account`. The code comment acknowledges this: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* The second branch of that disjunction is the flaw: a nonce-0 invoke passing validation says nothing about whether a nonce-1 invoke from the same account carries a valid signature.

When `skip_stateful_validations` returns `true`, `run_pre_validation_checks` propagates it as `skip_validate = true`: [3](#0-2) 

`run_validate_entry_point` then sets `validate: !skip_validate = false`: [4](#0-3) 

Inside `StatefulValidator::perform_validations`, when `execution_flags.validate == false` the function returns `Ok(())` immediately, before the `__validate__` call: [5](#0-4) 

The stateless validator only checks signature **length**, not cryptographic validity: [6](#0-5) 

`validate_by_mempool` (called before `skip_stateful_validations`) checks nonce and fee-escalation rules but never touches the signature: [7](#0-6) 

Therefore, the signature of the nonce-1 invoke is **never verified** anywhere in the gateway path.

### Impact Explanation

An attacker with a deployed account at on-chain nonce 0 can:

1. Submit a valid nonce-0 invoke → passes all checks including `__validate__`, enters the mempool.
2. Submit a nonce-1 invoke with an **invalid signature** (correct length, wrong values).
   - Stateless: passes (length within limit).
   - `validate_nonce`: `0 ≤ 1 ≤ 0 + max_gap` → passes.
   - `validate_by_mempool`: nonce 1 is fresh, no duplicate → passes.
   - `skip_stateful_validations`: `tx_nonce==1`, `account_nonce==0`, `account_tx_in_pool==true` → returns `true`.
   - `run_validate_entry_point`: `validate=false` → `__validate__` never called.
3. The invalid-signature transaction is admitted to the mempool.

This satisfies the **High** impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."*

### Likelihood Explanation

The trigger requires only that the attacker controls a deployed account (trivially achievable on any live network) and submits two sequential transactions. No privileged access, no special network position, and no race condition is required. The nonce-1 / account-nonce-0 window is the normal state for any account that has just sent its first transaction and is waiting for it to be committed.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** is pending for the sender address. The mempool should expose a dedicated query such as `has_pending_deploy_account(address) -> bool`, and `skip_stateful_validations` should only return `true` when that query confirms a deploy-account is in flight:

```rust
// Instead of:
return mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address()).await ...;

// Use:
return mempool_client.has_pending_deploy_account(tx.sender_address()).await ...;
```

This preserves the intended UX (deploy_account + invoke submitted together) while closing the bypass for accounts that have only non-deploy-account transactions in the mempool.

### Proof of Concept

```
1. Deploy account contract at address X (on-chain nonce becomes 0).
2. POST /gateway/add_transaction:
     Invoke { sender: X, nonce: 0, signature: <valid ECDSA sig> }
   → Accepted; X now appears in mempool pool.

3. POST /gateway/add_transaction:
     Invoke { sender: X, nonce: 1, signature: [0x0, 0x0]  /* invalid */ }
   → Gateway stateless check: signature length 2 ≤ max_signature_length → OK.
   → validate_nonce: 0 ≤ 1 ≤ max_gap → OK.
   → validate_by_mempool: nonce 1 not duplicate → OK.
   → skip_stateful_validations:
         tx.nonce() == 1  ✓
         account_nonce == 0  ✓
         account_tx_in_pool_or_recent_block(X) == true  ✓  (step 2 tx is in pool)
       → returns true
   → run_validate_entry_point(skip_validate=true):
         execution_flags.validate = false
         StatefulValidator::perform_validations returns Ok(()) without calling __validate__
   → Transaction ACCEPTED into mempool with invalid signature.
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-458)
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L180-194)
```rust
    fn validate_tx_signature_size(
        &self,
        tx: &RpcTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        let signature = tx.signature();

        let signature_length = signature.0.len();
        if signature_length > self.config.max_signature_length {
            return Err(StatelessTransactionValidatorError::SignatureTooLong {
                signature_length,
                max_signature_length: self.config.max_signature_length,
            });
        }

        Ok(())
```
