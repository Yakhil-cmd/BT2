### Title
Gateway `skip_stateful_validations` Admits Invoke Transactions with Invalid Signatures to the Mempool When a Deploy-Account Is Pending - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway stateful validator bypasses the `__validate__` entry-point call (the account contract's signature verification) for any Invoke transaction with nonce=1 when the sender's on-chain nonce is 0 and any transaction from that address exists in the mempool or a recent block. An unprivileged attacker who observes a pending `deploy_account` for a pre-funded address can submit an Invoke with an arbitrary (invalid) signature for that address, and the gateway will admit it to the mempool without ever verifying the signature. The invalid transaction is only rejected at execution time, after consuming mempool resources and charging a fee from the victim's pre-funded balance.

### Finding Description

**Root cause — missing authorization check on a specific admission path**

`StatelessTransactionValidator::validate` and the normal stateful path both enforce that the account contract's `__validate__` entry point is called to verify the transaction signature. However, `skip_stateful_validations` creates an explicit bypass:

```
crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 429-461
```

The function returns `true` (skip) when all three conditions hold:
1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed on-chain).
4. `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true`. [1](#0-0) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags`: [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `validate = false` the function returns immediately after `perform_pre_validation_stage`, never calling `__validate__`: [3](#0-2) 

`perform_pre_validation_stage` checks nonce, fee bounds, balance, and proof facts — but **not** the signature: [4](#0-3) 

**Exploit path**

1. Victim pre-funds address `X` and submits a `deploy_account` transaction to the gateway. The `deploy_account` enters the mempool.
2. Attacker monitors the public mempool, observes the pending `deploy_account` for `X`.
3. Attacker crafts an `Invoke` for `X` with `nonce=1` and an arbitrary (all-zero) signature, with fee bounds sufficient to pass `verify_can_pay_committed_bounds` (the pre-funded balance covers it).
4. Gateway's `run_pre_validation_checks` calls `validate_state_preconditions` (nonce=1 ≥ account_nonce=0, within gap — passes), then `validate_by_mempool` (nonce ordering — passes), then `skip_stateful_validations` — returns `true` because `deploy_account` is in the mempool.
5. `run_validate_entry_point` is called with `skip_validate=true`; `__validate__` is never invoked. The invalid Invoke is admitted to the mempool.
6. If the attacker's Invoke carries a higher tip/fee than the victim's legitimate Invoke (also nonce=1), the mempool replaces the victim's transaction with the attacker's.
7. Batcher executes: `deploy_account` succeeds (account deployed), then the attacker's Invoke is executed — `__validate__` now runs and fails (invalid signature) → transaction reverted, fee charged from victim's balance.
8. Victim's legitimate Invoke has been evicted from the mempool and must be resubmitted.

The `account_tx_in_pool_or_recent_block` check does **not** verify that the mempool entry is specifically a `deploy_account`; any transaction from the address suffices, as noted in the code comment: [5](#0-4) 

### Impact Explanation

This matches **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing**. An Invoke transaction whose signature would be rejected by the account contract's `__validate__` entry point is unconditionally admitted to the mempool. Concrete effects:

- **Invalid-signature transactions enter the mempool** for any pre-funded undeployed account that has a pending `deploy_account`.
- **Victim's legitimate Invoke is displaced** if the attacker submits a higher-fee replacement at the same nonce.
- **Victim's pre-funded balance is drained** by the fee charged for the reverted invalid Invoke at execution time.
- **No privileged access required** — the attacker only needs to observe the public mempool.

### Likelihood Explanation

The `deploy_account + invoke` UX flow is an explicitly supported and documented pattern (integration tests exist for it). Any user following this flow is vulnerable during the window between submitting `deploy_account` and the transaction being included in a block. The mempool is observable, making the front-running straightforward.

### Recommendation

The skip should not bypass signature verification entirely. Two options:

1. **Restrict the skip to the gateway's own submitted pair**: tag the `deploy_account` and its companion `invoke` at submission time (e.g., via a session token or by verifying the `invoke` was submitted in the same gateway request), and only skip `__validate__` for that specific pair.
2. **Perform a lightweight off-chain signature pre-check** before admitting the transaction to the mempool, even when `skip_validate = true`, so that obviously invalid signatures are rejected at the gateway boundary.

### Proof of Concept

```
# Preconditions:
# - Account address X is pre-funded with STRK.
# - Victim submits deploy_account for X (signed correctly). It enters the mempool.

# Attacker step:
invoke_tx = build_invoke_tx(
    sender_address = X,
    nonce          = 1,
    signature      = [0x0, 0x0],   # invalid signature
    resource_bounds = <sufficient to pass verify_can_pay_committed_bounds>,
    tip            = victim_tip + 1,  # outbid victim's invoke
)
gateway.add_tx(invoke_tx)

# Gateway evaluation:
#   validate_state_preconditions: nonce 1 >= account_nonce 0 → PASS
#   validate_by_mempool:          nonce ordering → PASS
#   skip_stateful_validations:    nonce==1, account_nonce==0,
#                                 account_tx_in_pool_or_recent_block==true → returns true
#   run_validate_entry_point:     validate=false → __validate__ NOT called → ADMITTED

# Batcher execution:
#   deploy_account executes → X is deployed
#   attacker's invoke executes → __validate__ called → FAILS (bad sig) → REVERTED
#   fee charged from X's balance
#   victim's invoke was evicted from mempool (replaced by higher-fee attacker invoke)
``` [6](#0-5) [1](#0-0) [7](#0-6)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L307-312)
```rust
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
