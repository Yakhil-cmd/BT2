### Title
Gateway Skips Signature Validation for Invoke Transactions via Overly Broad `skip_stateful_validations` Condition — (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful transaction validator completely bypasses the account's `__validate__` entry point (the only on-chain signature check) for invoke transactions with nonce=1 when `account_tx_in_pool_or_recent_block` returns `true`. The check is too broad: it returns `true` for **any** transaction from the account in the mempool, not exclusively a `deploy_account`. An unprivileged attacker who observes a victim's `deploy_account` entering the mempool can immediately inject a forged invoke (nonce=1, arbitrary wrong signature) for the victim's address, and the gateway will admit it without verifying the signature.

---

### Finding Description

`skip_stateful_validations` is the UX feature that lets a user submit `deploy_account` + `invoke` simultaneously, before the account is deployed on-chain. The condition for skipping the `__validate__` call is:

```
tx.nonce() == 1  AND  account_nonce == 0  AND  account_tx_in_pool_or_recent_block(sender) == true
``` [1](#0-0) 

`account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

`state.contains_account` returns `true` if the address appears in either the `committed` or `staged` nonce maps — i.e., for **any** transaction type (invoke, declare, or deploy_account) that has ever been seen for that address. [3](#0-2) 

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [4](#0-3) 

Inside `StatefulValidator::perform_validations`, when `validate == false` for an invoke, execution returns immediately after `perform_pre_validation_stage` — the `__validate__` entry point is never called:

```rust
tx.perform_pre_validation_stage(self.state(), &tx_context)?;
if !tx.execution_flags.validate {
    return Ok(());
}
// `__validate__` call.
let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
``` [5](#0-4) 

`perform_pre_validation_stage` checks nonce ordering, fee bounds, and proof facts — but **not** the signature: [6](#0-5) 

The only other checks before this point are the stateless validator (which checks signature **length**, not validity) and `validate_by_mempool` (which checks nonce ordering, duplicate hash, and fee escalation — not the signature): [7](#0-6) 

The comment in `skip_stateful_validations` claims: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* This reasoning is flawed: the presence of **any** transaction for the address (including a `deploy_account` submitted by the victim) satisfies the check, regardless of whether the attacker controls the account.

---

### Impact Explanation

An attacker who observes a victim's `deploy_account` for address X entering the mempool can submit a forged invoke for X with nonce=1 and an arbitrary (invalid) signature. The gateway admits it without calling `__validate__`. The forged invoke occupies the nonce=1 slot in the mempool. If the victim subsequently submits their legitimate invoke at nonce=1, the mempool either rejects it as `DuplicateNonce` or requires the victim to pay a higher fee to displace the attacker's transaction via fee escalation. When the batcher eventually executes the forged invoke, `__validate__` is called and fails; the transaction is reverted and marked rejected. The victim must resubmit. The attacker can repeat this indefinitely to prevent the victim's first post-deploy invoke from being sequenced.

**Matched impact**: *High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.*

---

### Likelihood Explanation

- Requires no privilege: any observer of the public mempool can execute this.
- The precondition (a `deploy_account` in the mempool) is a normal, common user action.
- The attack is cheap: the attacker's forged invoke fails at `__validate__` during execution, but the attacker can set fees just above the victim's to win fee escalation.
- The attack is repeatable: after each batcher cycle rejects the forged invoke, the attacker can re-inject.

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **deploy_account** transaction for the sender address is present in the mempool. Add a dedicated `deploy_account_in_pool(address)` query to the mempool API that inspects the pool for a `DeployAccount` transaction at nonce=0 for the given address. Only skip `__validate__` when that specific condition holds.

---

### Proof of Concept

1. Victim submits `deploy_account` for address `X` (nonce=0, valid signature). Gateway admits it; mempool now has `X` in `tx_pool`.

2. Attacker calls `add_tx` with an `invoke` for address `X`, nonce=1, calldata=`[]`, signature=`[0x1337]` (invalid).

3. Gateway flow:
   - Stateless validator: signature length 1 ≤ `max_signature_length` → passes. [8](#0-7) 
   - `convert_rpc_tx_to_internal_and_executable_txs`: computes tx hash, no signature check.
   - `extract_state_nonce_and_run_validations`: `account_nonce = 0` (X not deployed).
   - `validate_state_preconditions`: nonce 1 ≥ 0 → passes; resource bounds → passes.
   - `validate_by_mempool`: nonce 1 ≥ 0 → passes; no duplicate hash → passes.
   - `skip_stateful_validations`: nonce==1 ✓, account_nonce==0 ✓, `account_tx_in_pool_or_recent_block(X)` → `tx_pool.contains_account(X)` == **true** (victim's deploy_account is there) → returns **true**.
   - `run_validate_entry_point` called with `skip_validate=true` → `validate=false` → `__validate__` **never called**.
   - Forged invoke admitted to mempool. [9](#0-8) 

4. Victim submits their legitimate invoke for X, nonce=1. Mempool returns `DuplicateNonce` (or requires fee escalation above attacker's fee).

5. Batcher eventually processes the forged invoke: `__validate__` is called, fails (wrong signature), transaction reverted and rejected. Victim must resubmit.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-84)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
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
