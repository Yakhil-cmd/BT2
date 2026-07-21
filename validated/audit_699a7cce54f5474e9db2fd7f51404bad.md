### Title
Gateway Admits Invoke Transactions with Invalid Signatures via `skip_stateful_validations` UX Bypass — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry point — the only place where a transaction's cryptographic signature is verified — for any invoke transaction with `nonce=1` when the account has not yet been deployed but has a `deploy_account` transaction in the mempool. An unprivileged attacker who observes a victim's `deploy_account` transaction in the mempool can submit a malicious invoke transaction with an invalid (but correctly-sized) signature for the victim's address. The gateway admits this transaction without signature verification, blocking the victim's legitimate first post-deploy invoke.

---

### Finding Description

**Invariant broken**: Every transaction admitted to the mempool must carry a valid signature over its fields (including nonce, chain ID, calldata, resource bounds). The gateway's stateful validation path is the enforcement point for this invariant via the `__validate__` entry point.

**Root cause in `skip_stateful_validations`:** [1](#0-0) 

When all three conditions hold simultaneously:
1. The transaction is an `Invoke`
2. `tx.nonce() == Nonce(Felt::ONE)`
3. `account_nonce == Nonce(Felt::ZERO)`
4. `account_tx_in_pool_or_recent_block(sender)` returns `true`

…the function returns `true` (skip validation). This propagates into `run_validate_entry_point`: [2](#0-1) 

With `skip_validate = true`, `ExecutionFlags.validate` is set to `false`, so `StatefulValidator::validate` (which calls `tx.validate_tx(...)` — the `__validate__` entry point) is never invoked: [3](#0-2) 

**What the stateless validator checks:** Only signature *length*, not cryptographic validity: [4](#0-3) 

**What the mempool's `validate_tx` checks:** Only nonce range and fee escalation — no signature: [5](#0-4) 

**The full gateway admission path:** [6](#0-5) 

`run_pre_validation_checks` calls `validate_state_preconditions` (nonce + resource bounds), `validate_by_mempool` (nonce range), and then `skip_stateful_validations`. None of these verify the signature cryptographically. When `skip_validate=true`, `run_validate_entry_point` sets `validate=false` and the `__validate__` entry point is never called. [7](#0-6) 

**`account_tx_in_pool_or_recent_block` is trivially satisfied by the victim's own deploy_account:** [8](#0-7) 

---

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions.**

An attacker submits an invoke transaction with an invalid (but correctly-sized) signature for a victim's undeployed account address. The gateway admits it to the mempool without signature verification. The mempool then rejects the victim's legitimate nonce=1 invoke with `DuplicateNonce`, blocking the victim's first post-deploy transaction. The invalid transaction will eventually fail during blockifier execution (when `__validate__` runs with the real account class), but by then the victim's slot is occupied.

Secondary effect: the sequencer wastes execution resources on a transaction that is guaranteed to fail.

---

### Likelihood Explanation

- `deploy_account` transactions are publicly visible in the mempool.
- The attacker only needs to submit a correctly-sized but cryptographically invalid signature (e.g., two arbitrary `Felt` values, within `max_signature_length = 4000`).
- The race window is the time between the victim's `deploy_account` entering the mempool and the victim submitting their nonce=1 invoke — a window that is deliberately widened by the UX feature itself.
- No privileged access is required; any unprivileged user can call `POST /add_transaction`.

---

### Recommendation

The `skip_stateful_validations` function should not skip signature verification entirely. Options:

1. **Verify signature against the declared class**: The `deploy_account` transaction in the mempool contains the `class_hash` and `constructor_calldata`. The gateway can instantiate the account class and call `__validate__` against the undeployed account's expected state, rather than skipping it entirely.

2. **Restrict the skip to the submitter's own transaction**: Require that the invoke transaction's `tx_hash` matches a hash derived from the same sender that submitted the `deploy_account`, preventing third-party injection.

3. **Remove the skip entirely**: Accept the UX regression (users must wait for `deploy_account` to be included before submitting nonce=1 invokes) in exchange for correct admission invariants.

---

### Proof of Concept

```
1. Alice submits deploy_account(class_hash=C, salt=S, ...) → tx_hash=H_deploy
   → Mempool admits it; account_tx_in_pool_or_recent_block(Alice) = true

2. Attacker observes H_deploy in the mempool.

3. Attacker submits:
     Invoke(
       sender_address = Alice,
       nonce          = 1,
       signature      = [0xdeadbeef, 0xcafebabe],  // invalid, but length ≤ 4000
       calldata       = [<arbitrary>],
       resource_bounds = <valid>,
     )

4. Gateway stateless validation:
     validate_tx_signature_size: len=2 ≤ 4000 → PASS

5. Gateway stateful validation:
     get_nonce_from_state(Alice) → 0          (account not deployed)
     validate_nonce: 0 ≤ 1 ≤ 200 → PASS
     validate_by_mempool: no existing nonce=1 for Alice → PASS
     skip_stateful_validations:
       tx is Invoke ✓, nonce=1 ✓, account_nonce=0 ✓,
       account_tx_in_pool_or_recent_block(Alice) = true ✓
       → returns true (SKIP __validate__)
     run_validate_entry_point(skip_validate=true):
       ExecutionFlags { validate: false, ... }
       → __validate__ NOT called → PASS

6. Attacker's tx admitted to mempool with nonce=1 for Alice.

7. Alice submits her legitimate invoke(nonce=1, valid_signature):
     validate_by_mempool → DuplicateNonce { address: Alice, nonce: 1 }
     → REJECTED

8. Alice's first post-deploy invoke is blocked.
   Attacker's tx will fail during blockifier execution (invalid signature),
   but Alice's legitimate tx has already been rejected.
```

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-94)
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
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L180-195)
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
