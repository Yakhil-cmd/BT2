### Title
Gateway `skip_stateful_validations` skips `__validate__` signature check for Invoke nonce=1 when any transaction for the sender exists in the mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry point (signature verification) for any Invoke transaction with `nonce=1` when the account's on-chain nonce is `0` and `account_tx_in_pool_or_recent_block` returns `true`. An attacker who observes a victim's pending `deploy_account` transaction in the mempool can submit an unsigned Invoke(nonce=1) for the victim's address. The gateway admits this transaction without any signature check. When the blockifier later executes it, `__validate__` fails, but the nonce is already incremented and the fee is charged from the victim's balance.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` returns `true` (skip `__validate__`) when three conditions hold simultaneously:

1. The transaction is an Invoke with `tx.nonce() == Nonce(Felt::ONE)`
2. The on-chain account nonce is `Nonce(Felt::ZERO)`
3. `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true` [1](#0-0) 

The third condition is satisfied whenever the account has **any** transaction in the mempool pool or was seen in a recent committed block: [2](#0-1) 

For a fresh account (on-chain nonce=0), `tx_pool.contains_account` is true as soon as a `deploy_account` transaction for that address is in the pool. An attacker who observes a victim's `deploy_account` in the mempool (via P2P propagation) can immediately submit `Invoke(nonce=1, sender=victim_address)` with an arbitrary or empty signature.

The gateway's `run_validate_entry_point` sets `validate: !skip_validate`, so when `skip_validate=true`, `StatefulValidator::perform_validations` returns `Ok(())` after `perform_pre_validation_stage` without ever calling the `__validate__` entry point: [3](#0-2) 

`perform_pre_validation_stage` with `strict_nonce_check=false` accepts nonce=1 when account_nonce=0, and `verify_can_pay_committed_bounds` passes if the victim's address is pre-funded (the counterfactual deployment pattern): [4](#0-3) 

The transaction is admitted to the mempool. When the blockifier later executes the block:

1. `deploy_account` executes: account deployed, nonce advances to 1.
2. Attacker's `Invoke(nonce=1)` executes: `__validate__` is now called (blockifier always validates), fails with invalid signature, transaction is reverted — but the nonce has already been incremented to 2 and the fee is charged from the victim's balance.

The victim's legitimate nonce=1 transaction is now permanently invalid (`NonceTooOld`).

The `validate_nonce` check does not block this because `max_allowed_nonce_gap=200` allows nonce=1 when account_nonce=0: [5](#0-4) 

The `validate_by_mempool` call also does not check signatures: [6](#0-5) 

### Impact Explanation

**High** — Gateway/mempool admission accepts an invalid (unsigned) Invoke transaction before sequencing. When executed, it consumes the victim's nonce=1 slot and drains fee tokens from a pre-funded counterfactual account. The victim's legitimate first post-deploy transaction is permanently blocked.

### Likelihood Explanation

**Medium** — Requires (1) observing a victim's `deploy_account` in the mempool (possible via P2P gossip), (2) the victim's address being pre-funded before deployment (standard counterfactual wallet pattern), and (3) submitting before the `deploy_account` is committed. All three conditions are realistic in production.

### Recommendation

Replace the loose `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction exists in the pool for the sender address. The current check comment acknowledges the ambiguity ("either it has a deploy_account transaction or transactions with future nonces that passed validations") but the latter case is impossible for a fresh account, making the check misleadingly broad and exploitable.

```rust
// Instead of:
return mempool_client
    .account_tx_in_pool_or_recent_block(tx.sender_address())
    .await ...

// Use a dedicated check:
return mempool_client
    .deploy_account_tx_in_pool(tx.sender_address())
    .await ...
```

Alternatively, add a `nonReentrant`-equivalent guard: do not skip `__validate__` unless the mempool can confirm the pending transaction for that address is specifically a `deploy_account` type.

### Proof of Concept

```
1. Victim submits deploy_account(class_hash=C, salt=S) → address A computed deterministically
   → deploy_account enters mempool pool; account_nonce(A) = 0 on-chain

2. Attacker observes A in mempool via P2P

3. Attacker submits Invoke(sender=A, nonce=1, calldata=[drain_funds], signature=[])
   Gateway stateful validation:
     - validate_nonce: 0 <= 1 <= 200 ✓
     - verify_can_pay_committed_bounds: A is pre-funded ✓
     - skip_stateful_validations:
         nonce==1 ✓, account_nonce==0 ✓
         account_tx_in_pool_or_recent_block(A) == true (deploy_account is in pool) ✓
         → returns true (skip __validate__)
     - __validate__ NOT called → transaction admitted to mempool

4. Blockifier executes block:
   a. deploy_account(A): account deployed, nonce(A) = 1
   b. Invoke(A, nonce=1): __validate__ called → FAILS (invalid sig)
      → revert, but nonce(A) = 2, fee charged from A's balance

5. Victim's legitimate Invoke(A, nonce=1) → rejected: NonceTooOld
``` [7](#0-6)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L287-296)
```rust
            _ => {
                let max_allowed_nonce =
                    Nonce(account_nonce.0 + Felt::from(self.config.max_allowed_nonce_gap));
                if !(account_nonce <= incoming_tx_nonce && incoming_tx_nonce <= max_allowed_nonce) {
                    return Err(create_error(format!(
                        "Invalid transaction nonce. Expected: {account_nonce} <= nonce <= \
                         {max_allowed_nonce}, got: {incoming_tx_nonce}."
                    )));
                }
            }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L413-424)
```rust
/// Perform transaction validation by the mempool.
async fn validate_by_mempool(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<()> {
    let validation_args = ValidationArgs::new(tx, account_nonce);
    mempool_client
        .validate_tx(validation_args)
        .await
        .map_err(|err| mempool_client_err_to_deprecated_gw_err(&tx.signature(), err))
}
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-460)
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
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-94)
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
