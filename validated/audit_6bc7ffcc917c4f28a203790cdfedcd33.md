### Title
Signature Verification Bypassed for Invoke Transactions via `skip_stateful_validations` — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`skip_stateful_validations` skips the blockifier `__validate__` entry point (the only signature check) for any Invoke transaction with `nonce=1` sent to an account whose on-chain nonce is `0`, provided `account_tx_in_pool_or_recent_block` returns `true` for that sender address. Because that helper returns `true` for **any** transaction type in the pool — not specifically a deploy-account — an attacker who observes a victim's pending `DeployAccount` in the mempool can submit a forged Invoke with `nonce=1` and an invalid (or absent) signature, have it admitted to the mempool without signature verification, and cause the victim to pay fees for a reverted transaction or have their own legitimate first Invoke displaced.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` implements a UX shortcut: when a user sends `DeployAccount + Invoke(nonce=1)` simultaneously, the gateway cannot yet run `__validate__` on the Invoke because the account does not exist on-chain yet. The code therefore skips blockifier validation when:

1. The transaction is an Invoke with `tx.nonce() == 1`
2. The on-chain account nonce is `0`
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true` [1](#0-0) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `validate = false` the function returns `Ok(())` immediately after `perform_pre_validation_stage`, never calling `tx.validate_tx(...)` (the `__validate__` entry point): [3](#0-2) 

The authorization check that is skipped is the `__validate__` call at line 84, which is the **only** place where the account's signature is verified.

The condition for skipping is checked against `account_tx_in_pool_or_recent_block`, which returns `true` if **any** transaction for the address is in the pool — not specifically a `DeployAccount`: [4](#0-3) 

The code comment claims this is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." The second branch is unreachable (an Invoke with nonce ≥ 2 cannot pass blockifier validation when the account does not exist), so the only real trigger is a `DeployAccount` in the pool. However, the check does not distinguish between a `DeployAccount` submitted by the **victim** and one submitted by the **attacker** for the same address.

### Impact Explanation

An attacker who observes victim Alice's `DeployAccount` in the public mempool can:

1. Submit `Invoke(sender=Alice, nonce=1, calldata=<anything>, signature=<invalid>)` with a tip higher than Alice's own pending `Invoke(nonce=1)`.
2. The gateway's `skip_stateful_validations` sees Alice's `DeployAccount` in the pool, returns `true`, and the forged Invoke is admitted without any signature check.
3. The forged Invoke replaces Alice's legitimate Invoke in the mempool via fee-escalation logic.
4. The batcher executes: `DeployAccount` (succeeds, Alice's account is now live), then the forged `Invoke(nonce=1)` with `validate=true` — `__validate__` runs, fails, the transaction reverts, and the revert fee is charged from Alice's balance.
5. Alice's legitimate first Invoke has been evicted from the mempool and must be resubmitted.

This is a direct analog to the external bug: the code assumes the presence of a transaction in the pool proves the sender controls the account, without explicitly verifying the authorization token (signature) for the incoming transaction.

### Likelihood Explanation

The attack requires only that the victim's `DeployAccount` be visible in the mempool (which is public) and that the attacker outbid the victim's tip for `nonce=1`. Both conditions are trivially achievable by any unprivileged network participant. The window is the time between the victim's `DeployAccount` entering the mempool and the block being committed.

### Recommendation

Replace the generic `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `DeployAccount` transaction for the sender address is pending. Alternatively, add a check that the incoming Invoke's `sender_address` matches the `contract_address` field of a pending `DeployAccount` in the mempool, so that only the account owner (who controls the deploy parameters) can benefit from the skip.

### Proof of Concept

```
1. Alice broadcasts:
     DeployAccount(class=C, salt=S, calldata=D)  → computes address A, nonce=0
     Invoke(sender=A, nonce=1, calldata=<transfer>, sig=<valid>)

2. Attacker observes Alice's DeployAccount in the mempool.
   account_tx_in_pool_or_recent_block(A) == true

3. Attacker broadcasts:
     Invoke(sender=A, nonce=1, calldata=<drain>, sig=<garbage>, tip=Alice_tip+1)

4. Gateway stateful validator:
     account_nonce(A) == 0  ✓
     tx.nonce() == 1        ✓
     account_tx_in_pool_or_recent_block(A) == true  ✓
     → skip_stateful_validations returns true
     → __validate__ is NOT called
     → forged Invoke admitted to mempool

5. Fee-escalation: attacker's higher-tip Invoke replaces Alice's Invoke(nonce=1).

6. Batcher block:
     execute DeployAccount → A deployed, nonce→1
     execute forged Invoke(nonce=1) with validate=true
       → __validate__ fails → revert
       → revert fee charged from A's balance

7. Alice's legitimate Invoke is gone; she must resubmit and pay again.
``` [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L68-95)
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
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```
