### Title
Signature Bypass via `skip_stateful_validations` Allows Unsigned Invoke Admission and Victim Invoke Rejection — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`skip_stateful_validations` in the gateway's stateful validator omits the `__validate__` entry-point call (and therefore signature verification) for any Invoke transaction with `nonce == 1` submitted against an address whose deploy-account is already in the mempool. An attacker who observes a victim's pending `deploy_account` can front-run the victim's first invoke by submitting their own unsigned/arbitrarily-signed invoke for the victim's address. The gateway admits the attacker's transaction without verifying the signature; the victim's legitimate invoke is then rejected by the mempool with `DuplicateNonce`.

### Finding Description

**Step 1 – Validation skip decision.**

`skip_stateful_validations` returns `true` (skip `__validate__`) when all three conditions hold:

```
tx.nonce() == Nonce(Felt::ONE)
account_nonce == Nonce(Felt::ZERO)
mempool_client.account_tx_in_pool_or_recent_block(sender_address) == true
``` [1](#0-0) 

The third condition is satisfied by the presence of *any* transaction from that address in the mempool — including the victim's own `deploy_account`.

**Step 2 – Signature verification is skipped.**

When `skip_validate == true`, `run_validate_entry_point` sets `ExecutionFlags { validate: false, … }` and calls `StatefulValidator::validate`. Inside `perform_validations`, the branch for `Invoke` returns `Ok(())` immediately after `perform_pre_validation_stage` without ever calling `validate_tx` / `__validate__`: [2](#0-1) [3](#0-2) 

**Step 3 – Mempool duplicate-nonce guard blocks the victim.**

`validate_by_mempool` is a *validation-only* call that does not mutate the pool. It passes for the attacker's transaction because the victim's invoke is not yet in the pool. After the gateway admits the attacker's transaction via `mempool_client.add_tx`, the victim submits their own invoke (nonce=1). Now `validate_by_mempool` → `validate_fee_escalation` finds an existing `(address, nonce=1)` entry and returns `MempoolError::DuplicateNonce`, rejecting the victim's transaction: [4](#0-3) [5](#0-4) 

**Step 4 – Fee check passes using victim's balance.**

`perform_pre_validation_stage` calls `verify_can_pay_committed_bounds` against the victim's account balance. Because the victim funded their account before deployment (standard Starknet UX), this check passes regardless of who submitted the transaction: [6](#0-5) 

### Impact Explanation

The gateway admits an invalid (unsigned) invoke transaction and simultaneously causes the victim's valid, signed invoke to be rejected with `DuplicateNonce`. This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

The attacker's transaction will fail at execution time (the deployed account's `__validate__` will reject the bad signature), but the victim's transaction has already been discarded at the gateway. The victim must detect the failure, wait for the attacker's transaction to be processed, and resubmit — a window the attacker can exploit repeatedly for a sustained DoS.

### Likelihood Explanation

- The victim's `deploy_account` is publicly visible in the mempool.
- The attacker only needs the victim's contract address (derivable from the public `deploy_account` transaction fields).
- No private key material is required; the attacker supplies arbitrary calldata and signature bytes.
- The fee check uses the victim's on-chain balance, so the attacker does not need to hold any funds.
- The attack window is the interval between the victim's `deploy_account` entering the mempool and the victim submitting their first invoke — a common pattern in Starknet wallet UX.

### Recommendation

Inside `skip_stateful_validations`, verify that the transaction in the mempool for the sender address is specifically a `deploy_account` transaction (not just any transaction), **and** add a check that the incoming invoke's `tx_hash` was signed by the account's expected key before skipping `__validate__`. Alternatively, mirror the `PyValidator` approach and gate the skip on a configurable `max_nonce_for_validation_skip` that is actually enforced in the gateway path (the config field `max_nonce_for_validation_skip` exists in `StatefulTransactionValidatorConfig` but is not used by `skip_stateful_validations`): [7](#0-6) 

### Proof of Concept

1. Victim calls `add_tx(deploy_account { sender=A, nonce=0, sig=valid })` → gateway accepts, mempool holds it.
2. Attacker calls `add_tx(invoke { sender=A, nonce=1, calldata=arbitrary, sig=0x0 })`:
   - `validate_by_mempool`: pool has no `(A, nonce=1)` → passes.
   - `skip_stateful_validations`: `nonce==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(A)==true` → returns `true`.
   - `run_validate_entry_point`: `ExecutionFlags { validate: false }` → `__validate__` never called.
   - Gateway calls `mempool_client.add_tx(attacker_invoke)` → pool now holds `(A, nonce=1, sig=0x0)`.
3. Victim calls `add_tx(invoke { sender=A, nonce=1, calldata=real, sig=valid })`:
   - `validate_by_mempool` → `validate_fee_escalation` finds existing `(A, nonce=1)` → `MempoolError::DuplicateNonce` → **victim's transaction rejected**.
4. Attacker's transaction is eventually executed; `__validate__` fails; transaction reverts. Victim must resubmit — and the attacker can repeat step 2 indefinitely.

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L437-456)
```rust
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

**File:** crates/apollo_mempool/src/mempool.rs (L768-773)
```rust
        if !self.config.static_config.enable_fee_escalation {
            if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
                return Err(MempoolError::DuplicateNonce { address, nonce });
            };

            return Ok(None);
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

**File:** crates/apollo_gateway_config/src/config.rs (L283-283)
```rust
    pub max_nonce_for_validation_skip: Nonce,
```
