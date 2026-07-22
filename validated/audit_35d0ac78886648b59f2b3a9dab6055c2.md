### Title
Gateway Admits Nonce-1 Invoke Transactions with Invalid Signatures via Overly Broad `skip_stateful_validations` Check — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function skips `__validate__` (signature verification) for nonce-1 invoke transactions when `account_tx_in_pool_or_recent_block` returns `true`. This check is too broad: it returns `true` for any account with **any** transaction in the mempool pool, not specifically for accounts with a pending `deploy_account`. An attacker who observes a victim's pending `deploy_account` can submit a nonce-1 invoke for the victim's address with a garbage signature and a higher fee. The gateway admits it without signature verification, the mempool replaces the victim's legitimate invoke via fee escalation, and when the block is executed the garbage invoke fails at `__validate__` while charging the victim's account the fee.

---

### Finding Description

**Root cause — `skip_stateful_validations` uses an overly broad proxy**

`skip_stateful_validations` is designed to improve UX for the deploy_account + invoke simultaneous submission pattern. When an invoke with `nonce == 1` arrives for an account whose on-chain nonce is `0`, it calls `account_tx_in_pool_or_recent_block` to decide whether to skip `__validate__`: [1](#0-0) 

`account_tx_in_pool_or_recent_block` returns `true` if the account has **any** transaction in the pool or has ever appeared in a committed block: [2](#0-1) 

The comment in `skip_stateful_validations` claims this is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." This reasoning is flawed: the presence of **any** transaction for the account (including a future-nonce invoke that was itself admitted via skip_validate) satisfies the check, even when no `deploy_account` is pending.

**How the skip propagates to suppress signature verification**

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` is called with `skip_validate = true`: [3](#0-2) 

This sets `execution_flags.validate = false`. Inside `StatefulValidator::perform_validations`, when `validate` is `false`, the function returns after `perform_pre_validation_stage` without ever calling `__validate__`: [4](#0-3) 

`perform_pre_validation_stage` only checks nonce ordering, fee bounds, and balance — it does **not** verify the transaction signature: [5](#0-4) 

**Fee escalation allows replacement without signature check**

The mempool's `validate_fee_escalation` only checks fee amounts, not signatures. A replacement transaction with a sufficiently higher fee passes mempool validation regardless of its signature: [6](#0-5) 

**Execution charges the victim**

During block execution, `execution_flags.validate` defaults to `true`, so `__validate__` is called on the garbage invoke. It fails (invalid signature), the transaction is reverted, and the fee is charged to the victim's account via `execute_fee_transfer`: [7](#0-6) 

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An attacker can submit a nonce-1 invoke with an invalid signature for any victim account that has a pending `deploy_account` in the mempool. The gateway admits it without signature verification. The mempool replaces the victim's legitimate invoke. At execution time the garbage invoke fails, charging the victim fees and permanently consuming their nonce-1 slot until they resubmit.

---

### Likelihood Explanation

The deploy_account + invoke simultaneous submission pattern is explicitly supported and documented as a UX feature: [8](#0-7) 

Any user deploying a new account and submitting their first invoke simultaneously is vulnerable. The attacker only needs to observe the mempool for pending `deploy_account` transactions (public information) and submit a replacement with a slightly higher fee.

---

### Recommendation

Replace the overly broad `account_tx_in_pool_or_recent_block` check with a specific `deploy_account_in_pool(account_address)` query that returns `true` only when a `deploy_account` transaction (i.e., `InternalRpcTransactionWithoutTxHash::DeployAccount`) is present in the pool for the given address. This preserves the intended UX improvement while closing the signature-bypass path.

```rust
// In skip_stateful_validations, replace:
return mempool_client
    .account_tx_in_pool_or_recent_block(tx.sender_address())
    .await
    ...

// With:
return mempool_client
    .deploy_account_in_pool(tx.sender_address())
    .await
    ...
```

Add a corresponding `deploy_account_in_pool` method to `Mempool` that checks `tx_pool` specifically for `DeployAccount` transactions at nonce 0 for the given address.

---

### Proof of Concept

1. Victim pre-funds address `A` with STRK and submits `deploy_account` (nonce 0, valid signature) + `invoke` (nonce 1, valid signature, fee `F`). Both are admitted to the mempool. `tx_pool.contains_account(A)` is now `true`.

2. Attacker submits `invoke` for address `A` with nonce 1, **garbage signature**, and fee `F + 1`.

3. **Gateway stateful path**: `get_nonce_from_state(A)` returns `Nonce(0)`. `tx.nonce() == 1 && account_nonce == 0` → `skip_stateful_validations` calls `account_tx_in_pool_or_recent_block(A)` → returns `true` (victim's `deploy_account` is in pool) → `skip_validate = true`. [9](#0-8) 

4. `run_validate_entry_point` sets `execution_flags.validate = false`. `perform_pre_validation_stage` passes (nonce 1 ≥ 0, balance covers fee). `__validate__` is **never called**. Garbage invoke is admitted. [10](#0-9) 

5. **Mempool**: `validate_fee_escalation` passes (`F+1 > F`). Victim's nonce-1 invoke is replaced by the garbage invoke.

6. **Block execution**: `deploy_account` executes (nonce 0) → account `A` deployed. Garbage invoke executes (nonce 1) → `__validate__` called → signature invalid → transaction reverted → fee charged to `A`.

The victim's legitimate invoke is permanently displaced; the victim loses fees and must resubmit at nonce 2.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-314)
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

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L68-96)
```rust
    pub fn perform_validations(&mut self, tx: AccountTransaction) -> StatefulValidatorResult<()> {
        // Deploy account transaction should be fully executed, since the constructor must run
        // before `__validate_deploy__`. The execution already includes all necessary validations,
        // so they are skipped here.
        // Declare transaction should also be fully executed - otherwise, if we only go through
        // the validate phase, we would miss the check that the class was not declared before.
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L550-591)
```rust
    fn execute_fee_transfer(
        state: &mut dyn State,
        tx_context: Arc<TransactionContext>,
        actual_fee: Fee,
    ) -> TransactionExecutionResult<CallInfo> {
        // The least significant 128 bits of the amount transferred.
        let lsb_amount = Felt::from(actual_fee.0);
        // The most significant 128 bits of the amount transferred.
        let msb_amount = Felt::ZERO;

        let TransactionContext { block_context, tx_info } = tx_context.as_ref();
        let storage_address = tx_context.fee_token_address();
        // The fee contains the cost of running this transfer, and the token contract is
        // well known to the sequencer, so there is no need to limit its run.
        let mut remaining_gas_for_fee_transfer =
            block_context.versioned_constants.os_constants.gas_costs.base.default_initial_gas_cost;
        let fee_transfer_call = CallEntryPoint {
            class_hash: None,
            code_address: None,
            entry_point_type: EntryPointType::External,
            entry_point_selector: selector_from_name(constants::TRANSFER_ENTRY_POINT_NAME),
            calldata: calldata![
                *block_context.block_info.sequencer_address.0.key(), // Recipient.
                lsb_amount,
                msb_amount
            ],
            storage_address,
            caller_address: tx_info.sender_address(),
            call_type: CallType::Call,

            initial_gas: remaining_gas_for_fee_transfer,
        };
        let mut context = EntryPointExecutionContext::new_invoke(
            tx_context,
            true,
            SierraGasRevertTracker::new(GasAmount(remaining_gas_for_fee_transfer)),
        );

        Ok(fee_transfer_call
            .execute(state, &mut context, &mut remaining_gas_for_fee_transfer)
            .map_err(|error| Box::new(TransactionFeeError::ExecuteFeeTransferError(error)))?)
    }
```

**File:** crates/apollo_integration_tests/src/utils.rs (L713-726)
```rust
/// Generates a deploy account transaction followed by an invoke transaction from the same account.
/// The first invoke_tx can be inserted to the first block right after the deploy_tx due to
/// the skip_validate feature. This feature allows the gateway to accept this transaction although
/// the account does not exist yet.
pub fn create_deploy_account_tx_and_invoke_tx(
    tx_generator: &mut MultiAccountTransactionGenerator,
    account_id: AccountId,
) -> Vec<RpcTransaction> {
    let undeployed_account_tx_generator = tx_generator.account_with_id_mut(account_id);
    assert!(!undeployed_account_tx_generator.is_deployed());
    let deploy_tx = undeployed_account_tx_generator.generate_deploy_account();
    let invoke_tx = undeployed_account_tx_generator.generate_trivial_rpc_invoke_tx(1);
    vec![deploy_tx, invoke_tx]
}
```
