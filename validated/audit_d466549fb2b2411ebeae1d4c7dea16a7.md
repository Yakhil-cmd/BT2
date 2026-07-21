Looking at the `skip_stateful_validations` logic in the gateway's stateful validator, I can identify a valid analog to M08.

---

### Title
Signature Bypass via `skip_stateful_validations` Allows Attacker to Inject Unsigned Invoke Transactions into Mempool — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function unconditionally skips the `__validate__` entry point (signature verification) for any invoke transaction with `nonce == 1` when the account nonce is `0` and any transaction for that address exists in the mempool or a recent block. An unprivileged attacker who observes a victim's `deploy_account` transaction in the mempool can frontrun the victim's subsequent invoke transaction by submitting a malicious invoke with the victim's sender address and an invalid signature. Because the gateway never calls `__validate__`, the malicious transaction is admitted to the mempool, displacing the victim's legitimate transaction.

### Finding Description

In `skip_stateful_validations`:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
}
```

When this returns `true`, `run_pre_validation_checks` returns `skip_validate = true`. [1](#0-0) 

`run_validate_entry_point` then sets `validate = !skip_validate = false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `validate == false`, the function returns immediately after `perform_pre_validation_stage` without ever calling `__validate__`:

```rust
tx.perform_pre_validation_stage(self.state(), &tx_context)?;
if !tx.execution_flags.validate {
    return Ok(());
}
// `__validate__` call.
let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
``` [3](#0-2) 

`perform_pre_validation_stage` only checks nonce, fee bounds, and balance — it does **not** verify the signature: [4](#0-3) 

The comment in `skip_stateful_validations` states: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* This reasoning is circular: a nonce-1 transaction that itself skipped validation via this same path is counted as evidence that validation was passed, which it was not.

`account_tx_in_pool_or_recent_block` checks for **any** transaction for the address, not specifically a `deploy_account`. An attacker's own malicious nonce-1 transaction, once admitted, satisfies this condition for subsequent queries. [5](#0-4) 

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions and rejects valid transactions before sequencing.**

The attacker can:
1. Observe victim Alice's `deploy_account` (nonce 0) in the mempool.
2. Submit a malicious invoke with `sender_address = Alice`, `nonce = 1`, `signature = [0, 0]`, and valid resource bounds.
3. The gateway admits it without calling `__validate__` (signature never checked).
4. Alice's legitimate invoke (nonce 1) is subsequently rejected by the mempool as a duplicate nonce.
5. The batcher eventually drops the malicious transaction when `__validate__` fails at execution time, but Alice's transaction has already been evicted.
6. The attacker can repeat this indefinitely, permanently blocking Alice's first post-deploy invoke.

The broken invariant is: **every transaction admitted to the mempool must have passed signature verification by the account's `__validate__` entry point, or must be provably safe to skip (e.g., the account is already deployed and the deploy_account is in a confirmed block).**

### Likelihood Explanation

Medium. The attack requires:
- Monitoring the mempool for `deploy_account` transactions (public information).
- Submitting the malicious invoke before the victim does (a narrow but exploitable race window, especially since the victim typically submits both transactions in quick succession).
- No privileged access, no special keys, no knowledge of the victim's private key.

The attack is cheap to execute and can be automated.

### Recommendation

1. **Restrict the skip condition to confirmed blocks only**: change `account_tx_in_pool_or_recent_block` to only check recent blocks (not the mempool). This eliminates the race window entirely.
2. **Or, verify the signature format independently of `__validate__`**: perform a lightweight ECDSA/Stark-curve signature check on the transaction hash before admitting to the mempool, even when skipping the full `__validate__` entry point.
3. **Or, check specifically for a `deploy_account` transaction** rather than any transaction for the address, so that an attacker's own previously-injected nonce-1 transaction cannot serve as the skip trigger.

### Proof of Concept

```
1. Alice submits deploy_account(nonce=0, class_hash=C, salt=S) → address A is known.
2. Attacker submits invoke(sender=A, nonce=1, calldata=X, signature=[0,0],
                           resource_bounds=valid).
   Gateway path:
     skip_stateful_validations: nonce==1 ∧ account_nonce==0 ∧
       account_tx_in_pool_or_recent_block(A)==true  →  skip_validate=true
     run_validate_entry_point: validate=false  →  __validate__ NOT called
     → tx admitted to mempool.
3. Alice submits invoke(sender=A, nonce=1, calldata=Y, signature=valid).
   Mempool rejects: duplicate nonce for address A.
4. Batcher executes deploy_account(A), then malicious invoke(A, nonce=1):
     __validate__ called → fails (invalid signature) → tx dropped, not included.
5. Alice's nonce-1 slot is now free but her tx was already rejected.
   Attacker repeats from step 2.
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-314)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L355-372)
```rust
    pub fn perform_pre_validation_stage<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let tx_info = &tx_context.tx_info;
        Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;

        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
        }

        self.validate_proof_facts(&tx_context.block_context, state)?;

        Ok(())
    }
```
