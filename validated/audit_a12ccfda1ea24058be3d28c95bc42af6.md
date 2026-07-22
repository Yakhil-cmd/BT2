### Title
`skip_stateful_validations` admits unsigned invoke transactions for any address with a pending deploy_account — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function is designed to improve UX by allowing an invoke transaction (nonce=1) to bypass `__validate__` entry-point execution when a deploy_account for the same address is pending in the mempool. However, the check that gates this bypass — `account_tx_in_pool_or_recent_block(sender_address)` — is exploitable by any third party: an attacker who observes a victim's deploy_account in the mempool can immediately submit their own invoke transaction for the victim's address with nonce=1 and an arbitrary/invalid signature, and the gateway will admit it to the mempool without ever calling `__validate__`.

---

### Finding Description

The relevant code path in `extract_state_nonce_and_run_validations` is:

1. `get_nonce_from_state` → returns `Nonce(0)` for an undeployed address.
2. `run_pre_validation_checks` → calls `validate_state_preconditions`, `validate_by_mempool`, then `skip_stateful_validations`.
3. `run_validate_entry_point(executable_tx, skip_validate=true)` → sets `execution_flags.validate = false`, so `StatefulValidator::perform_validations` returns early without calling `__validate__`. [1](#0-0) 

The skip condition is:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await ...
}
``` [2](#0-1) 

The comment's reasoning is: "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." This reasoning is flawed. The check does not verify that the *current* transaction's signature is valid — it only checks whether *any* transaction from that address is in the mempool. An attacker who is not the account owner can satisfy this condition by observing the victim's deploy_account in the mempool.

The `validate_nonce` check for invoke transactions allows nonce=1 when account_nonce=0 (within the allowed gap): [3](#0-2) 

The `validate_by_mempool` call only checks nonce ordering and fee escalation — it does not verify signatures: [4](#0-3) 

When `skip_validate=true`, `run_validate_entry_point` sets `validate: false` and the blockifier's `perform_validations` returns without calling `__validate__`: [5](#0-4) [6](#0-5) 

---

### Impact Explanation

An attacker can inject invoke transactions with arbitrary/invalid signatures for any address that has a pending deploy_account in the mempool. These transactions pass all gateway checks and are admitted to the mempool without signature verification. This matches the allowed impact: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

At block execution time the batcher will call `__validate__` (since `validate=true` is the default for execution), so the attacker's transaction will revert. However:

- The mempool is polluted with signature-invalid transactions, enabling a targeted DoS against any account in the process of being deployed.
- The attacker can front-run the deploy_account window to fill the victim's nonce-1 slot in the mempool with a transaction the victim did not authorize, potentially delaying or displacing the victim's own legitimate nonce-1 invoke (if the mempool enforces one-tx-per-nonce-per-address via fee escalation rules).

---

### Likelihood Explanation

- The mempool is observable (transactions are propagated over P2P).
- The attack window is the time between the deploy_account entering the mempool and being committed to a block — typically multiple seconds.
- No privileged access is required; any unprivileged actor can submit an RPC transaction.
- The only cost is the resource bounds (gas) attached to the crafted invoke, which will be charged on revert.

---

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a check that specifically confirms a **deploy_account** transaction for the sender address is pending, rather than any transaction. Alternatively, require that the invoke transaction carry a valid signature even when the account is not yet deployed (e.g., by running `__validate__` against the class hash declared in the pending deploy_account, as the Python gateway does). At minimum, document that the current check is intentionally permissive and add a rate-limit or fee-escalation guard to prevent mempool flooding.

---

### Proof of Concept

1. Victim submits `DeployAccount` for address `A` (class_hash `C`, salt `S`, constructor_calldata `D`). The transaction enters the mempool; `account_tx_in_pool_or_recent_block(A)` now returns `true`.

2. Attacker submits `Invoke` with `sender_address=A`, `nonce=1`, arbitrary `calldata`, and a garbage `signature`.

3. Gateway stateless check passes (signature length ≤ max, resource bounds valid).

4. `get_nonce_from_state(A)` → `Nonce(0)` (account not yet deployed).

5. `validate_nonce`: account_nonce=0, tx_nonce=1 → within allowed gap → **passes**.

6. `validate_by_mempool`: checks nonce ordering only → **passes**.

7. `skip_stateful_validations`: tx_nonce=1, account_nonce=0, `account_tx_in_pool_or_recent_block(A)=true` → returns `true`.

8. `run_validate_entry_point(skip_validate=true)`: `execution_flags.validate=false` → `__validate__` is **never called**.

9. Attacker's garbage-signed invoke is **admitted to the mempool** without signature verification. [7](#0-6)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L414-424)
```rust
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L74-95)
```rust
        match tx.tx {
            ApiTransaction::DeployAccount(_) | ApiTransaction::Declare(_) => self.execute(tx),
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
