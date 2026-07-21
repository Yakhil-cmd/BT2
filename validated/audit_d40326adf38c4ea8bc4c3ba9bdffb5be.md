### Title
Attacker Bypasses Account Signature Verification for Nonce-1 Invoke Transactions via `skip_stateful_validations` — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function unconditionally skips the `__validate__` entry point (the account's signature-verification function) for any invoke transaction with `nonce == 1` when the sender address has any entry in the mempool or recent-block state. Because the check is purely address-based and not caller-authenticated, an attacker who observes a victim's `deploy_account` transaction in the mempool can craft an invoke transaction from the victim's address with an arbitrary (invalid) signature and have it admitted to the mempool without any signature check.

### Finding Description

The stateful validation path in `extract_state_nonce_and_run_validations` is:

1. Read `account_nonce` from state.
2. Call `run_pre_validation_checks` → `validate_state_preconditions` (nonce range, resource-bound price) + `validate_by_mempool` (duplicate/nonce-order check) + `skip_stateful_validations` (returns `true` = skip `__validate__`).
3. Call `run_validate_entry_point(executable_tx, skip_validate)`. [1](#0-0) 

Inside `run_validate_entry_point`, the `validate` execution flag is set to `!skip_validate`: [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `execution_flags.validate == false` the function returns immediately after `perform_pre_validation_stage`, never calling the account's `__validate__` entry point: [3](#0-2) 

The skip decision is made in `skip_stateful_validations`: [4](#0-3) 

The condition is: transaction is `Invoke`, `tx.nonce() == 1`, `account_nonce == 0`, and `account_tx_in_pool_or_recent_block` returns `true`. The last check is: [5](#0-4) 

which returns `true` if the address appears in the mempool pool or in the committed/staged state — i.e., if the victim's `deploy_account` transaction is already in the mempool.

`perform_pre_validation_stage` (which still runs) checks nonce ordering and, when `charge_fee` is true, calls `verify_can_pay_committed_bounds`: [6](#0-5) 

This balance check is the only remaining guard. It passes as long as the victim's account address has been pre-funded with STRK (the standard UX requirement before submitting `deploy_account`).

**Attack steps:**

1. Victim funds their new account address `A` with STRK and submits `deploy_account` (nonce 0). The `deploy_account` enters the mempool — `account_tx_in_pool_or_recent_block(A)` now returns `true`.
2. Attacker observes the mempool, learns address `A`.
3. Attacker crafts `Invoke(sender=A, nonce=1, calldata=<arbitrary>, signature=<garbage>, resource_bounds=<valid>)`.
4. Gateway: `validate_nonce` passes (0 ≤ 1 ≤ 200), `validate_resource_bounds` passes (price check), `validate_by_mempool` passes (no duplicate hash), `skip_stateful_validations` returns `true` (account in pool, nonce==1, account_nonce==0).
5. `run_validate_entry_point` is called with `validate=false` → `__validate__` is never invoked → invalid-signature transaction is admitted.
6. Attacker's transaction is now in the mempool alongside the victim's legitimate `invoke(nonce=1)`. Via fee escalation the attacker can displace the victim's transaction. When executed, the attacker's transaction reaches `__validate__`, fails, reverts — but the nonce is consumed and a fee is charged to the victim's account.

### Impact Explanation

An invoke transaction with a forged/invalid signature is admitted to the mempool without signature verification. This satisfies the **High** impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."* Downstream consequences include: victim's nonce-1 slot consumed by the attacker's reverted transaction; victim's fee balance partially drained; victim's legitimate invoke permanently stuck until they submit a replacement at nonce 2.

### Likelihood Explanation

The preconditions are met in the standard Starknet UX flow: every new account must be funded before deploying, and the `deploy_account` + `invoke(nonce=1)` bundle is the documented pattern. The mempool is observable. No privileged access is required; any unprivileged network participant can execute the attack the moment a `deploy_account` appears in the mempool.

### Recommendation

The `skip_stateful_validations` function must not skip `__validate__` solely because the address appears in the mempool. Options:

1. **Restrict the skip to the exact deploy-account transaction hash**: require the caller to supply the hash of the pending `deploy_account` and verify it matches a transaction in the mempool for that address (as the `PyValidator` path does via `deploy_account_tx_hash`).
2. **Remove the skip entirely** and rely on the mempool's nonce-gap tolerance to hold the invoke until the `deploy_account` is committed.
3. **At minimum**, verify that the `deploy_account` transaction in the mempool was submitted by the same sender address and that its computed contract address matches the invoke's `sender_address`, so an attacker cannot piggyback on a victim's pending `deploy_account`.

### Proof of Concept

```
# Precondition: victim has funded address A and submitted deploy_account(nonce=0)
# Mempool now contains deploy_account for A → account_tx_in_pool_or_recent_block(A) == true

# Attacker crafts:
invoke_tx = InvokeV3(
    sender_address = A,          # victim's undeployed address
    nonce          = 1,          # post-deploy nonce
    calldata       = [<drain or arbitrary>],
    resource_bounds = <valid, covered by A's STRK balance>,
    signature      = [0xdeadbeef],  # garbage — never checked
)

# Gateway path:
# validate_nonce:  0 <= 1 <= 200  → OK
# validate_resource_bounds: price check → OK (attacker sets valid price)
# validate_by_mempool: no duplicate hash → OK
# skip_stateful_validations:
#   tx.nonce()==1 && account_nonce==0 && account_tx_in_pool_or_recent_block(A)==true
#   → returns true (skip __validate__)
# run_validate_entry_point(skip_validate=true):
#   execution_flags.validate = false
#   perform_pre_validation_stage: nonce OK, balance OK (A is funded)
#   → returns Ok(()) without calling __validate__
# Result: invalid-signature transaction admitted to mempool ✓
``` [4](#0-3) [3](#0-2)

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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
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
