### Title
Signature Bypass via `skip_stateful_validations` Allows Unauthorized Invoke Admission for Undeployed Accounts - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function unconditionally skips the `__validate__` entry point (the only place where an account contract verifies the transaction signature) for any invoke transaction with `nonce=1` targeting an address whose on-chain nonce is `0` and which has any transaction present in the mempool. Because the check uses only the attacker-controlled `sender_address` field and the mempool's presence of the victim's `deploy_account`, an unprivileged attacker can submit an invoke transaction for a victim's address with an invalid signature and have it admitted to the mempool, blocking the victim's legitimate nonce-1 invoke.

### Finding Description

In `skip_stateful_validations` at lines 429–461 of `crates/apollo_gateway/src/stateful_transaction_validator.rs`, the gateway skips the blockifier's `__validate__` call when three conditions hold simultaneously:

1. The incoming invoke transaction carries `nonce == 1`
2. The account's on-chain nonce is `0` (account not yet deployed)
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true` [1](#0-0) 

When these conditions are met, `run_pre_validation_checks` returns `skip_validate = true`. [2](#0-1) 

`run_validate_entry_point` then sets `validate: !skip_validate` (i.e., `validate: false`) and calls `blockifier_validator.validate(account_tx)`. [3](#0-2) 

Inside `StatefulValidator::perform_validations`, when `execution_flags.validate == false`, the function returns `Ok(())` immediately after `perform_pre_validation_stage`, without ever calling the account's `__validate__` entry point: [4](#0-3) 

`perform_pre_validation_stage` checks nonce, fee bounds, and proof facts — but **not the transaction signature**. Signature verification is exclusively the responsibility of the account contract's `__validate__` entry point: [5](#0-4) 

The code comment explains the intent — to support the UX pattern of sending `deploy_account + invoke` simultaneously: [6](#0-5) 

However, the check `account_tx_in_pool_or_recent_block(tx.sender_address())` only verifies that **some** transaction exists in the mempool for the sender address. It does not verify that the invoke was submitted by the account owner, nor that the transaction in the mempool is a `deploy_account`. An attacker who observes a victim's `deploy_account` in the mempool satisfies condition 3 without any authorization.

The mempool's `account_tx_in_pool_or_recent_block` implementation confirms it checks any transaction presence: [7](#0-6) 

The gateway's `validate_nonce` for invoke transactions allows nonce=1 when account_nonce=0 (within the allowed gap), so the nonce check also passes: [8](#0-7) 

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions.**

An attacker can submit an invoke transaction for any victim address that has a pending `deploy_account` in the mempool, using an arbitrary (invalid) signature. The transaction is admitted to the mempool without signature verification. Consequences:

- The attacker's transaction occupies the victim's nonce=1 slot in the mempool. The victim's legitimate invoke with nonce=1 is rejected with `MempoolError::DuplicateNonce`.
- When the block is built, the attacker's invoke executes on the victim's newly deployed account. The account's `__validate__` runs during actual execution and reverts the transaction — but the victim's nonce is still incremented and fees are charged.
- The attacker can repeat this for nonce=2, 3, … (after each block commit) to continuously grief the victim.

### Likelihood Explanation

**Medium.** The attack requires:
1. Observing a victim's `deploy_account` transaction in the public mempool (trivially observable).
2. Submitting an invoke for the victim's address before the victim submits their own nonce=1 invoke (a race condition, but the attacker has the full mempool propagation window).
3. The victim's account address must be pre-funded (standard practice for `deploy_account`).

No privileged access is required. The attacker only needs to submit a standard RPC transaction.

### Recommendation

The `skip_stateful_validations` function must not rely solely on mempool presence as a proxy for account ownership. Possible mitigations:

1. **Require the deploy_account and invoke to be submitted atomically** (e.g., as a bundle in a single RPC call), so the gateway can verify both originate from the same submitter.
2. **Restrict the skip to transactions submitted in the same gateway request** as the `deploy_account`, rather than checking the mempool state.
3. **Perform a lightweight signature pre-check** (e.g., ECDSA verification against the account's public key derived from the deploy_account's constructor calldata) even when skipping the full `__validate__` execution.

### Proof of Concept

```
1. Alice submits deploy_account(address=0xALICE, nonce=0, sig=valid)
   → Gateway admits it; mempool now contains Alice's deploy_account.

2. Attacker observes Alice's deploy_account in the mempool.

3. Attacker submits invoke(sender=0xALICE, nonce=1, calldata=[malicious], signature=[])
   → Gateway stateless check: passes (non-zero resource bounds, valid address, etc.)
   → Gateway stateful check:
       account_nonce = get_nonce_from_state(0xALICE) = 0  ✓
       validate_nonce: 0 <= 1 <= max_gap  ✓
       validate_by_mempool: no duplicate nonce=1 for Alice  ✓
       skip_stateful_validations:
           tx.nonce() == 1  ✓
           account_nonce == 0  ✓
           account_tx_in_pool_or_recent_block(0xALICE) == true  ✓
           → returns true (skip __validate__)
       run_validate_entry_point: validate=false → returns Ok(()) immediately
   → Attacker's invoke admitted to mempool WITHOUT signature verification.

4. Alice submits invoke(sender=0xALICE, nonce=1, calldata=[legitimate], signature=valid)
   → Mempool rejects: MempoolError::DuplicateNonce { address: 0xALICE, nonce: 1 }

5. Block is built:
   - Alice's deploy_account executes (nonce 0→1): account deployed.
   - Attacker's invoke executes (nonce 1→2): __validate__ runs, fails (invalid sig), tx reverts.
   - Alice's nonce is now 2; she paid fees for the attacker's failed transaction.
   - Alice must resubmit her invoke with nonce=2.

6. Attacker repeats from step 3 with nonce=2 to continue griefing.
```

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-314)
```rust
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L407-410)
```rust
        let skip_validate =
            skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
        Ok(skip_validate)
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L426-457)
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```
