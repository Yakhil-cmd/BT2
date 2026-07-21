### Title
Gateway `skip_stateful_validations` Admits Invoke Transactions with Unverified Signatures to the Mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the account's `__validate__` entry point for any invoke transaction with `nonce == 1` when the account has a pending deploy-account in the mempool. Because `__validate__` is the only place where the account's signature is verified, an attacker can submit an invoke transaction with a completely invalid signature that passes all gateway checks and is admitted to the mempool.

---

### Finding Description

The external bug's invariant is: *a contract must not delegate unlimited authorization to external components to act on its behalf; it must perform the critical operation itself.* In the sequencer, the analog is: *the gateway must not delegate signature verification to the blockifier/batcher; it must verify the account's `__validate__` entry point itself before admitting a transaction to the mempool.*

**The delegation path:**

In `extract_state_nonce_and_run_validations`, the gateway calls `run_pre_validation_checks`, which calls `skip_stateful_validations`: [1](#0-0) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags`: [2](#0-1) 

This means `blockifier_validator.validate(account_tx)` is called with `validate=false`. Inside `StatefulValidator::perform_validations`, the `__validate__` call is skipped entirely: [3](#0-2) 

The `__validate__` entry point is the only place where the account's signature is verified. `perform_pre_validation_stage` checks nonce, fee bounds, and proof facts — but not the signature: [4](#0-3) 

**The skip condition:**

The skip fires when:
1. The transaction is an `Invoke`
2. `tx.nonce() == Nonce(Felt::ONE)`
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed)
4. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true` [5](#0-4) 

Condition 4 is satisfied by the attacker's own valid `deploy_account` transaction already in the mempool.

**The batcher always re-validates:**

When the batcher picks up the transaction for execution, `AccountTransaction::new_for_sequencing` always sets `validate: true`: [6](#0-5) 

So the invalid transaction is rejected at execution time — but only after it has been admitted to the mempool and the batcher has spent resources on it.

---

### Impact Explanation

**High. Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

An attacker can inject invoke transactions with arbitrary (invalid) signatures into the mempool. Each such transaction:
- Passes all gateway stateless and stateful checks
- Enters the mempool
- Is picked up by the batcher
- Fails `__validate__` at execution time (invalid signature), causing the batcher to waste execution resources
- Is then discarded with no state change

Because the mempool check (`account_tx_in_pool_or_recent_block`) remains `true` as long as the deploy-account is pending or recently included, the attacker can repeatedly inject invalid invokes with `nonce=1` from the same address, each time wasting batcher resources. With many funded addresses, this becomes a sustained DoS against the sequencer's execution pipeline.

---

### Likelihood Explanation

**Medium.** The attacker must:
1. Fund an address with enough STRK to cover the deploy-account fee
2. Submit a valid `deploy_account` for that address (passes all validations)
3. Submit an invoke with `nonce=1` and an invalid signature

Step 2 requires real funds, but a single funded address enables repeated injection of invalid invokes. Multiple addresses multiply the effect. No privileged access is required; this is reachable through the normal public gateway endpoint.

---

### Recommendation

The analog to the external bug's fix is: *perform the critical authorization check (signature verification via `__validate__`) inside the gateway itself, rather than delegating it to the blockifier at execution time.*

Concretely, when `skip_stateful_validations` returns `true`, the gateway should still verify the transaction's signature through an alternative means — for example, by running a lightweight signature check against the declared account class, or by restricting the skip to only cases where the signature can be structurally validated (e.g., the signature matches the expected format for the class hash in the deploy-account). At minimum, the gateway should not admit a transaction whose signature is provably invalid (e.g., empty or zero-length when the account class requires a non-empty signature).

---

### Proof of Concept

1. Choose a target account class hash `C` (e.g., the standard OpenZeppelin account).
2. Derive address `X` from `C`, a salt, and constructor calldata containing attacker's public key `pk`.
3. Fund address `X` with enough STRK for the deploy-account fee.
4. Submit `deploy_account(class_hash=C, salt=..., constructor_calldata=[pk])` with a valid signature → enters mempool; `account_tx_in_pool_or_recent_block(X)` now returns `true`.
5. Submit `invoke(sender=X, nonce=1, calldata=..., signature=[0x0, 0x0])` (invalid signature).
6. Gateway calls `skip_stateful_validations`: `nonce==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(X)==true` → returns `true`.
7. `run_validate_entry_point` sets `validate=false` → `__validate__` is never called → transaction is admitted to the mempool.
8. Batcher executes the deploy-account (nonce 0→1), then picks up the invoke (nonce 1), runs `__validate__`, which fails due to the invalid signature. Transaction is rejected, state rolled back.
9. Repeat step 5 indefinitely (nonce is never incremented for the failed invoke), each time wasting batcher execution resources.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
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
