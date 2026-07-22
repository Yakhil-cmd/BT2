### Title
Signature Verification Bypass via `skip_stateful_validations` Allows Unauthorized Invoke Execution on Undeployed Accounts — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function unconditionally skips the account's `__validate__` entry point for any invoke transaction with `nonce == 1` when the on-chain account nonce is `0` and any transaction from that sender address exists in the mempool. An unprivileged attacker who observes a `deploy_account` transaction in the mempool can front-run it by submitting an arbitrary invoke transaction from the victim's address with `nonce = 1` and any (or no) signature. The gateway accepts this transaction without ever calling `__validate__`, allowing the attacker to execute arbitrary calls from the victim's not-yet-deployed account.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` implements a UX shortcut: when a user submits `deploy_account + invoke` simultaneously, the invoke's `__validate__` is skipped because the account does not yet exist on-chain. [1](#0-0) 

The skip condition is:
1. Transaction type is `Invoke`
2. `tx.nonce() == Nonce(Felt::ONE)`
3. `account_nonce == Nonce(Felt::ZERO)`
4. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true`

Condition 4 checks whether **any** transaction from the sender address is in the mempool or a recent block — it does not verify that the existing mempool transaction is a `deploy_account`, nor does it verify that the incoming invoke was submitted by the account owner. An attacker who sees Alice's `deploy_account` in the mempool satisfies all four conditions by submitting an invoke from Alice's address with `nonce = 1`.

When `skip_validate = true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags`: [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `execution_flags.validate == false`, the function returns immediately after `perform_pre_validation_stage` without ever calling `__validate__`: [3](#0-2) 

`perform_pre_validation_stage` only checks the nonce and fee bounds — it does not verify the signature: [4](#0-3) 

The mempool's `validate_tx` (called before `skip_stateful_validations`) only checks for duplicate tx_hash and nonce ordering — it does not verify the cryptographic signature either: [5](#0-4) 

### Impact Explanation

An attacker can execute arbitrary calldata from any victim account that is in the process of being deployed. Concretely:

1. Alice broadcasts `deploy_account(nonce=0)` — it enters the mempool.
2. Attacker observes Alice's address in the mempool and broadcasts `invoke(sender=Alice, nonce=1, calldata=<drain_funds>)` with a garbage or empty signature.
3. Gateway evaluates: `tx.nonce()==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(Alice)==true` → `skip_validate=true` → `__validate__` is never called → transaction is admitted.
4. Alice's `deploy_account` is sequenced first; her account is deployed.
5. The attacker's invoke (nonce=1) executes with Alice's account, running arbitrary calldata without Alice's authorization.
6. Alice's own invoke (nonce=1) is subsequently rejected as `NonceTooOld`.

This matches the **Critical** impact: "Invalid or unauthorized Starknet transaction accepted through account validation, signature, nonce, chain id, fee/resource bound, paymaster, or account-deployment logic."

### Likelihood Explanation

The attack requires only mempool observation (publicly available) and the ability to submit a transaction before the victim. Any mempool-monitoring bot can automate this. The window is open for every new account deployment on the network. No privileged access is required.

### Recommendation

The `skip_stateful_validations` check must be restricted to transactions that were submitted by the legitimate account owner. The correct fix is to verify that the incoming invoke transaction was signed by the account's public key even when skipping the on-chain `__validate__` call, **or** to restrict the skip to only the specific invoke transaction that was submitted alongside the `deploy_account` (e.g., by checking the tx_hash against a paired submission). At minimum, the check in `account_tx_in_pool_or_recent_block` should be strengthened to confirm the existing mempool entry is specifically a `deploy_account` transaction for the same address, not just any transaction. [6](#0-5) 

### Proof of Concept

```
1. Alice submits:
     deploy_account_tx = DeployAccount { sender_address: ALICE, nonce: 0, ... }
   → Mempool accepts it. account_tx_in_pool_or_recent_block(ALICE) == true.

2. Attacker submits (before Alice's invoke):
     malicious_invoke = Invoke {
         sender_address: ALICE,
         nonce: 1,
         calldata: [drain_alice_funds(...)],
         signature: [],   // empty or garbage — never checked
         resource_bounds: <valid>,
     }

3. Gateway stateful validation:
     account_nonce = state.get_nonce(ALICE) = 0
     validate_nonce: 0 <= 1 <= 200 → OK
     validate_by_mempool: no duplicate nonce → OK
     skip_stateful_validations:
         tx.nonce() == 1 ✓
         account_nonce == 0 ✓
         account_tx_in_pool_or_recent_block(ALICE) == true ✓
         → returns skip_validate = true
     run_validate_entry_point(skip_validate=true):
         ExecutionFlags { validate: false, ... }
         StatefulValidator::perform_validations → returns after pre_validation_stage
         __validate__ is NEVER called
     → Malicious invoke admitted to mempool.

4. Block is built:
     deploy_account(ALICE, nonce=0) executes → ALICE deployed.
     malicious_invoke(ALICE, nonce=1) executes → drain_alice_funds() runs.

5. Alice's legitimate invoke(nonce=1) → rejected: NonceTooOld.
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

**File:** crates/apollo_mempool/src/mempool.rs (L702-711)
```rust
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
