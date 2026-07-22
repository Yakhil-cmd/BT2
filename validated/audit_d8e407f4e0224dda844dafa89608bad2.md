### Title
Signature Bypass via `skip_stateful_validations` Allows Unsigned Invoke Admission for Pre-Deployment Accounts - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

`skip_stateful_validations` skips the `__validate__` entry-point call (signature verification) for any invoke transaction with `nonce=1` sent to an address whose `account_nonce=0` in state, whenever `account_tx_in_pool_or_recent_block` returns `true`. Because that check returns `true` for **any** transaction from the target address in the pool — not specifically a `deploy_account` — an unprivileged attacker who observes a victim's `deploy_account` in the mempool can submit a forged invoke with `nonce=1` for the victim's address, bypass signature verification at the gateway, and have the forged transaction admitted to the mempool. The mempool then rejects the victim's legitimate `nonce=1` invoke with `DuplicateNonce`, permanently breaking the deploy-account + invoke UX flow for that account.

### Finding Description

**Root cause — `skip_stateful_validations`:** [1](#0-0) 

When an invoke transaction satisfies `tx.nonce() == 1` and `account_nonce == 0`, the function calls `account_tx_in_pool_or_recent_block(sender_address)`. If that returns `true`, it returns `skip_validate = true`.

**`account_tx_in_pool_or_recent_block` is not deploy-account-specific:** [2](#0-1) 

It returns `true` for **any** transaction from the address in the pool or committed state — including a victim's `deploy_account` that an attacker merely observed.

**Effect of `skip_validate = true`:** [3](#0-2) 

`validate: !skip_validate` is set to `false`. Inside `StatefulValidator::perform_validations`: [4](#0-3) 

When `validate = false`, `perform_pre_validation_stage` still runs (nonce + fee checks), but the `__validate__` call is skipped entirely. The transaction is admitted without any signature check.

**Mempool rejects duplicate nonces:** [5](#0-4) 

Once the attacker's forged invoke occupies `(victim_address, nonce=1)`, the victim's legitimate invoke with the same nonce is rejected with `MempoolError::DuplicateNonce`. [6](#0-5) 

### Impact Explanation

The attacker permanently occupies the victim's `nonce=1` slot in the mempool with a transaction that will revert during batcher execution (because the batcher uses `ExecutionFlags::default()` with `validate=true`). The victim's legitimate `nonce=1` invoke is rejected. The victim's deploy-account + invoke UX flow is broken. This matches: **High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

### Likelihood Explanation

The mempool is public. Any observer can detect a `deploy_account` for a target address and race to submit a forged invoke with `nonce=1`. The victim's address is deterministic from constructor arguments, so the attacker can pre-compute it. The attack requires no privileged access and no on-chain funds beyond the gas fee (which the attacker pays from their own address, not the victim's).

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction for the sender address exists in the mempool. Add a dedicated mempool API such as `deploy_account_in_pool(address) -> bool` that inspects only `DeployAccount` transactions. Alternatively, require that the `deploy_account` transaction hash be included in the invoke transaction and verify it is present in the mempool before skipping `__validate__`.

### Proof of Concept

1. Victim pre-funds address `A` with STRK (required for the deploy+invoke UX flow).
2. Victim submits `deploy_account` for `A` (nonce=0) to the gateway. It enters the mempool.
3. Attacker observes `A` in the mempool via `account_tx_in_pool_or_recent_block`.
4. Attacker crafts an `RpcInvokeTransactionV3` with `sender_address=A`, `nonce=1`, `signature=[0x1, 0x2]` (arbitrary).
5. Gateway stateless validation passes (valid resource bounds, nonce DA mode L1, etc.).
6. `convert_rpc_tx_to_internal` computes `tx_hash` and produces `InternalRpcTransaction`.
7. `extract_state_nonce_and_run_validations` is called:
   - `get_nonce_from_state(A)` returns `Nonce(0)`.
   - `validate_state_preconditions`: nonce=1 is within `[0, 200]` → passes.
   - `validate_by_mempool`: no existing `(A, nonce=1)` in pool → passes.
   - `skip_stateful_validations`: nonce=1, account_nonce=0, `account_tx_in_pool_or_recent_block(A)=true` → returns `true`.
   - `run_validate_entry_point(skip_validate=true)`: `validate=false` → `__validate__` not called → `Ok(())`.
8. Attacker's forged invoke is sent to the mempool and admitted.
9. Victim submits legitimate invoke for `A` with `nonce=1` and correct signature.
10. Mempool rejects it: `MempoolError::DuplicateNonce { address: A, nonce: 1 }`. [7](#0-6) [8](#0-7)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L175-178)
```rust
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
```

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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-93)
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
```

**File:** crates/apollo_mempool_types/src/errors.rs (L8-9)
```rust
    #[error("Duplicate nonce, sender address: {address}, nonce: {:?}", nonce)]
    DuplicateNonce { address: ContractAddress, nonce: Nonce },
```
