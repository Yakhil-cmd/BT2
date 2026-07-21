### Title
`skip_stateful_validations` Admits Invalid-Signature Invoke Transactions and Enables Front-Running of the Deploy-Account+Invoke UX Flow — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function skips the `__validate__` entry-point call (the account's signature-verification step) for any Invoke transaction with `nonce == 1` when `account_tx_in_pool_or_recent_block` returns `true` for the sender address. Because that helper returns `true` for **any** transaction in the pool for the address — not only a `DeployAccount` — an attacker who observes a legitimate `DeployAccount` entering the mempool can immediately submit a nonce-1 Invoke with an **arbitrary or invalid signature** that bypasses gateway-level signature verification and is admitted to the mempool. The same `DuplicateNonce` guard that protects the pool then **rejects** the legitimate user's correctly-signed nonce-1 Invoke, permanently blocking the intended deploy-account+invoke UX flow for that account.

---

### Finding Description

**Root cause — `skip_stateful_validations`:** [1](#0-0) 

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            ...
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...;
        }
    }
    Ok(false)
}
```

When this returns `true`, `run_validate_entry_point` is called with `skip_validate = true`, and the blockifier's `StatefulValidator::perform_validations` exits before calling `__validate__`: [2](#0-1) 

The helper `account_tx_in_pool_or_recent_block` returns `true` if **any** transaction for the address is in the pool: [3](#0-2) 

The code comment asserts this is "sufficient" because the account "either has a deploy_account transaction or transactions with future nonces that passed validations." The second branch is the flaw: future-nonce Invokes pass the gateway's nonce-gap check without requiring the account to be deployed, so an attacker can plant one to trigger the skip for a nonce-1 Invoke.

**Attack path (front-running the legitimate deploy+invoke flow):**

1. Legitimate user submits `DeployAccount` for address X → passes all checks → enters mempool → `account_tx_in_pool_or_recent_block(X)` now returns `true`.

2. Attacker submits `Invoke(nonce=1, sender=X, signature=<garbage>)`:
   - `validate_nonce`: `0 ≤ 1 ≤ max_allowed_nonce_gap` → passes. [4](#0-3) 
   - `validate_by_mempool`: nonce 1 ≥ account nonce 0 → passes. [5](#0-4) 
   - `skip_stateful_validations`: nonce=1, account_nonce=0, X in pool → returns `true` → `__validate__` **not called**.
   - Attacker's invalid-signature Invoke is **admitted to the mempool**.

3. Legitimate user submits `Invoke(nonce=1, sender=X, signature=<valid>)`:
   - `validate_by_mempool` → `validate_fee_escalation` → nonce 1 already occupied → `MempoolError::DuplicateNonce` → **rejected**. [6](#0-5) 

4. Batcher executes `DeployAccount` → X is deployed.
5. Batcher executes attacker's `Invoke(nonce=1)` → `__validate__` **is** called (batcher does not skip) → invalid signature → transaction reverts.
6. Legitimate user's `Invoke(nonce=1)` was already rejected at step 3 and is gone.

**Result:** The legitimate user's deploy succeeded but their nonce-1 Invoke was permanently blocked. The attacker's invalid-signature transaction was admitted to the mempool and consumed sequencer execution resources.

---

### Impact Explanation

This matches the **High** impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

- An Invoke with an **invalid signature** (an invalid transaction) is **accepted** by the gateway and admitted to the mempool.
- The legitimate user's correctly-signed Invoke (a valid transaction) is **rejected** by the mempool's `DuplicateNonce` guard.
- The sequencer wastes execution resources on a transaction that will always revert.
- The attack can be repeated for every new `DeployAccount` observed in the mempool, making the deploy-account+invoke UX flow unreliable.

---

### Likelihood Explanation

- The `DeployAccount` transaction is public in the mempool (observable by any node).
- The attacker needs no private key, no special privilege, and no on-chain funds beyond the gas to submit the Invoke.
- The race window is the time between the `DeployAccount` entering the mempool and the legitimate user's nonce-1 Invoke arriving — typically milliseconds to seconds, but the attacker can submit immediately upon observing the `DeployAccount`.
- The `max_allowed_nonce_gap` default (≥ 2 based on tests) ensures nonce-2 Invokes also pass, providing an alternative trigger path.

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`DeployAccount` transaction** exists in the pool for the sender address. Add a dedicated `deploy_account_in_pool(address)` query to the mempool that inspects transaction types, and use that in `skip_stateful_validations`:

```rust
// Instead of:
mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address()).await

// Use:
mempool_client.deploy_account_in_pool(tx.sender_address()).await
```

This preserves the intended UX (deploy+invoke submitted simultaneously) while closing the window for invalid-signature Invokes to bypass `__validate__`.

---

### Proof of Concept

```
1. Deploy a known contract class (e.g. OpenZeppelin account) to obtain class_hash C.

2. Compute the deterministic address X for a DeployAccount with class_hash=C, salt=S.

3. Fund address X with enough STRK to cover fees.

4. Submit DeployAccount(class_hash=C, salt=S, nonce=0) → tx enters mempool.
   Confirm: account_tx_in_pool_or_recent_block(X) == true.

5. Submit Invoke(sender=X, nonce=1, calldata=[...], signature=[0x1, 0x2]) 
   (signature is two arbitrary felt values, not a valid ECDSA signature).
   
   Expected gateway response: transaction accepted (tx_hash returned).
   Observed: __validate__ is NOT called; invalid-signature Invoke is in the mempool.

6. Submit Invoke(sender=X, nonce=1, calldata=[...], signature=<valid ECDSA sig>)
   (the legitimate user's correctly-signed Invoke).
   
   Expected: accepted.
   Observed: rejected with DuplicateNonce error.

7. Wait for batcher to include the block:
   - DeployAccount executes successfully; X is deployed.
   - Attacker's Invoke(nonce=1) executes; __validate__ is called; 
     invalid signature → REVERTED.
   - Legitimate user's Invoke is absent from the block.
``` [1](#0-0) [7](#0-6) [8](#0-7)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L286-296)
```rust
            // Other transactions must be within the allowed nonce range.
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-95)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;

                // Post validations.
                PostValidationReport::verify(
                    &tx_context,
                    &actual_cost,
                    tx.execution_flags.charge_fee,
                )?;

                Ok(())
            }
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-711)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }

    fn validate_incoming_tx(
        &self,
        tx_reference: TransactionReference,
        incoming_account_nonce: Nonce,
    ) -> MempoolResult<()> {
        if self.tx_pool.get_by_tx_hash(tx_reference.tx_hash).is_ok() {
            return Err(MempoolError::DuplicateTransaction { tx_hash: tx_reference.tx_hash });
        }
        self.state.validate_incoming_tx(tx_reference, incoming_account_nonce)
    }
```
