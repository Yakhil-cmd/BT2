### Title
Gateway `skip_stateful_validations` Admits Invoke Transactions Without Signature Verification for Undeployed Accounts - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the gateway's stateful transaction validator skips the `__validate__` entry-point call for invoke transactions with nonce=1 when the sender account is not yet deployed but has a deploy-account transaction in the mempool. Because the account contract does not exist at validation time, the prerequisite for calling `__validate__` (a deployed account) is absent — analogous to calling `Router.exactInput` without a prior `approve`. Rather than failing, the code silently omits the signature check entirely. An unprivileged attacker can exploit this to inject an invoke transaction with an arbitrary signature and arbitrary calldata into the mempool, occupying the victim's nonce=1 slot before the victim's legitimate transaction arrives.

### Finding Description

In `skip_stateful_validations`, when an invoke transaction carries `nonce == 1`, the on-chain account nonce is `0` (account not yet deployed), and `account_tx_in_pool_or_recent_block` returns `true` (a deploy-account is queued), the function returns `true` — meaning "skip signature validation." [1](#0-0) 

This `true` value propagates to `run_validate_entry_point`, which constructs `ExecutionFlags { validate: !skip_validate, … }` — i.e., `validate: false`. [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `execution_flags.validate == false`, the function returns immediately after `perform_pre_validation_stage` without ever calling `__validate__`: [3](#0-2) 

`perform_pre_validation_stage` only checks nonce range (non-strict), fee bounds, and balance — none of which verify the transaction's signature: [4](#0-3) 

The balance check (`verify_can_pay_committed_bounds`) passes because the victim's address is pre-funded (standard Starknet deploy-account flow requires funding the address before deployment): [5](#0-4) 

The result: an invoke transaction with a completely invalid signature and arbitrary calldata is admitted to the mempool without any cryptographic authorization check.

### Impact Explanation

An attacker who observes a victim's `deploy_account` transaction in the mempool can immediately submit `invoke(sender=victim, nonce=1, calldata=anything, signature=garbage)`. The gateway accepts it because:

1. `validate_state_preconditions` passes (nonce=1 is within the allowed gap from account_nonce=0).
2. `validate_by_mempool` passes (no duplicate nonce exists yet).
3. `skip_stateful_validations` returns `true` (deploy_account is in the mempool).
4. `__validate__` is never called.

The malicious transaction occupies the victim's nonce=1 slot. The victim's legitimate invoke is subsequently rejected by the mempool as a duplicate nonce. When the batcher executes the block, the deploy-account succeeds, then the attacker's invoke is executed — `__validate__` is now called (account is deployed), it rejects the garbage signature, and the transaction reverts. The victim's first post-deployment transaction is permanently blocked for that block.

**Matching impact:** "High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."

### Likelihood Explanation

The attack requires only:
- Monitoring the public mempool for `deploy_account` transactions (trivially observable).
- Submitting a single crafted invoke transaction before the victim's invoke arrives.

No privileged access, no special knowledge of the victim's keys, and no on-chain funds are required. The race window is the time between the victim's `deploy_account` being admitted and the victim's `invoke(nonce=1)` arriving — typically seconds to minutes in practice.

### Recommendation

Before skipping `__validate__`, verify that the transaction in the mempool for the account is specifically a `deploy_account` transaction (not just any transaction). Alternatively, require that the invoke transaction's sender address matches the contract address computed from the deploy-account transaction's parameters, so only the legitimate deployer can benefit from the skip. A stricter fix is to require the caller to supply the deploy-account transaction hash and verify it matches a pending deploy-account in the mempool before granting the skip.

### Proof of Concept

1. Alice submits `deploy_account(class_hash=C, salt=S, constructor_data=D)` → contract address `A` is computed and the transaction enters the mempool.
2. Attacker observes `A` in the mempool.
3. Attacker submits `invoke(sender=A, nonce=1, calldata=[drain_all_funds], signature=[0x0, 0x0])`.
4. Gateway evaluation:
   - `get_nonce_from_state(A)` → `0` (not deployed).
   - `validate_state_preconditions`: nonce=1 ≥ 0, within gap → passes.
   - `validate_by_mempool`: no existing nonce=1 for `A` → passes.
   - `skip_stateful_validations`: nonce==1, account_nonce==0, `account_tx_in_pool_or_recent_block(A)` → `true` → returns `true`.
   - `run_validate_entry_point` with `validate=false` → `perform_validations` returns after pre-validation, `__validate__` never called.
5. Attacker's invoke is stored in the mempool at nonce=1 for address `A`.
6. Alice submits `invoke(sender=A, nonce=1, calldata=[legitimate], signature=[valid])` → mempool rejects: duplicate nonce.
7. Batcher: executes `deploy_account` (nonce=0, succeeds), then executes attacker's invoke (nonce=1) → `__validate__` called → signature `[0x0, 0x0]` rejected → transaction reverted with fee charged.
8. Alice's legitimate transaction is never executed. [6](#0-5)

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

**File:** crates/blockifier/src/fee/fee_utils.rs (L173-202)
```rust
pub fn verify_can_pay_committed_bounds(
    state: &mut dyn StateReader,
    tx_context: &TransactionContext,
) -> TransactionFeeResult<()> {
    let tx_info = &tx_context.tx_info;
    let committed_fee = tx_context.max_possible_fee();
    let (balance_low, balance_high, can_pay) =
        get_balance_and_if_covers_fee(state, tx_context, committed_fee)?;
    if can_pay {
        Ok(())
    } else {
        Err(match tx_info {
            TransactionInfo::Current(context) => match &context.resource_bounds {
                L1Gas(l1_gas) => TransactionFeeError::GasBoundsExceedBalance {
                    resource: Resource::L1Gas,
                    max_amount: l1_gas.max_amount,
                    max_price: l1_gas.max_price_per_unit,
                    balance: balance_to_big_uint(&balance_low, &balance_high),
                },
                AllResources(bounds) => TransactionFeeError::ResourcesBoundsExceedBalance {
                    bounds: *bounds,
                    balance: balance_to_big_uint(&balance_low, &balance_high),
                },
            },
            TransactionInfo::Deprecated(context) => TransactionFeeError::MaxFeeExceedsBalance {
                max_fee: context.max_fee,
                balance: balance_to_big_uint(&balance_low, &balance_high),
            },
        })
    }
```
