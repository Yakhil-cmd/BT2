### Title
Gateway `skip_stateful_validations` admits invoke transactions with arbitrary signatures via overly broad `account_tx_in_pool_or_recent_block` guard — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`skip_stateful_validations` is the exact sequencer analog of the PriceFeed Case 4 bug. In the PriceFeed, Case 4 transitions back to `chainlinkWorking` without running `_bothOraclesLiveAndUnbrokenAndSimilarPrice`, the consistency check that every other transition to that state requires. In the sequencer, the `skip_stateful_validations` path admits an invoke transaction to the mempool without running the account's `__validate__` entry point — the only place where the account's signature is verified — while every other invoke admission path runs it. The guard used to justify the skip (`account_tx_in_pool_or_recent_block`) is too broad: it returns `true` if the account has **any** transaction in the pool, including a previously-admitted nonce-1 invoke that itself skipped validation. This creates a self-referential trust chain that allows an attacker to replace a legitimate nonce-1 invoke with one carrying an arbitrary signature, bypassing all signature verification at the gateway level.

---

### Finding Description

**Root cause — `skip_stateful_validations`**

In `extract_state_nonce_and_run_validations`, after the nonce and resource-bound pre-checks pass, the gateway calls `run_validate_entry_point` with a `skip_validate` flag: [1](#0-0) 

`skip_stateful_validations` returns `true` — meaning "skip `__validate__`" — when three conditions hold simultaneously: [2](#0-1) 

1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)` (hardcoded).
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed in state).
4. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`.

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [3](#0-2) 

Inside the blockifier's `StatefulValidator::perform_validations`, when `validate = false` the function returns immediately after `perform_pre_validation_stage`, never calling `validate_tx`: [4](#0-3) 

`validate_tx` is the only place the account's `__validate__` entry point — which contains the signature check — is executed: [5](#0-4) 

`perform_pre_validation_stage` checks nonce, fee bounds, and balance, but **not** the signature: [6](#0-5) 

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks for duplicate tx hashes and nonce ordering — no signature verification: [7](#0-6) 

**The broken guard — `account_tx_in_pool_or_recent_block`**

The comment in `skip_stateful_validations` claims the check is sufficient because the account "either has a deploy_account transaction or transactions with future nonces that passed validations." This reasoning is circular: [8](#0-7) 

`tx_pool.contains_account(account_address)` returns `true` if the account has **any** transaction in the pool — including a nonce-1 invoke that was itself admitted via the skip path. Once a nonce-1 invoke is in the pool (step 2 of the attack below), the deploy_account can be evicted (TTL expiry or fee-escalation replacement), and the nonce-1 invoke alone keeps `account_tx_in_pool_or_recent_block` returning `true`. A subsequent nonce-1 invoke with an arbitrary signature and a higher fee then satisfies the skip condition and replaces the legitimate invoke via fee escalation: [9](#0-8) 

---

### Impact Explanation

The gateway admits an invoke transaction whose `signature` field has never been verified by the account's `__validate__` entry point. This directly satisfies the **High** impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

A concrete consequence: an attacker can replace a victim's legitimate nonce-1 invoke (submitted alongside a deploy_account) with an invoke carrying an invalid signature. The victim's deploy_account is committed and the account is deployed, but the intended invoke fails at execution time. The victim must resubmit, and the attacker can repeat the replacement indefinitely as long as the nonce-1 slot is open.

---

### Likelihood Explanation

The attack requires:
1. Knowing a target account address that has a deploy_account in the pool (observable from the public mempool or P2P gossip).
2. Submitting a nonce-1 invoke with a higher fee than the victim's.
3. Fee escalation being enabled (`enable_fee_escalation: true` in `MempoolStaticConfig`).

All three conditions are realistic in a live network. The attacker does not need any privileged access.

---

### Recommendation

**Short term:** Change `account_tx_in_pool_or_recent_block` to a type-specific check: only return `true` when the account has a **deploy_account** transaction in the pool (not any transaction). This closes the self-referential trust chain. Alternatively, track the deploy_account tx hash explicitly and verify it is still present before granting the skip.

**Long term:** Enumerate all paths where `execution_flags.validate = false` is set at the gateway level and ensure each one has a corresponding invariant that cannot be subverted by a third party. Document the security assumptions of the deploy+invoke UX feature explicitly.

---

### Proof of Concept

```
1. Attacker observes that victim submitted deploy_account (nonce=0) for address A.
   → deploy_account is in the mempool pool; account_tx_in_pool_or_recent_block(A) = true.

2. Attacker submits invoke_A_nonce1_valid (nonce=1, valid signature, fee=F).
   → skip_stateful_validations: nonce==1, account_nonce==0, pool contains deploy_account → skip=true.
   → __validate__ is NOT run. Invoke admitted to pool.
   → Now tx_pool.contains_account(A) = true (due to this invoke itself).

3. Attacker fee-escalates the deploy_account out of the pool (or waits for TTL expiry).
   → deploy_account is gone. tx_pool still contains invoke_A_nonce1_valid.
   → account_tx_in_pool_or_recent_block(A) still = true.

4. Attacker submits invoke_A_nonce1_INVALID (nonce=1, ARBITRARY signature, fee=F+1).
   → skip_stateful_validations: nonce==1, account_nonce==0, pool contains nonce-1 invoke → skip=true.
   → __validate__ is NOT run. Invalid invoke admitted.
   → Fee escalation replaces invoke_A_nonce1_valid with invoke_A_nonce1_INVALID.

5. Victim's deploy_account is eventually committed → account A is deployed.
   invoke_A_nonce1_INVALID is executed → __validate__ runs on-chain → fails (invalid signature).
   Victim's intended action is not executed.
```

The exact corrupted value is the `signature` field of the admitted invoke transaction: it is never verified by `__validate__` at the gateway, violating the invariant that all invoke transactions in the mempool carry a signature that has passed account-level verification. [10](#0-9) [11](#0-10) [8](#0-7)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L175-178)
```rust
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-312)
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
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

**File:** crates/apollo_mempool/src/mempool.rs (L760-791)
```rust
    fn validate_fee_escalation(
        &self,
        incoming_tx_reference: TransactionReference,
    ) -> MempoolResult<Option<TransactionReference>> {
        let TransactionReference { address, nonce, .. } = incoming_tx_reference;

        self.validate_no_delayed_declare_front_run(incoming_tx_reference)?;

        if !self.config.static_config.enable_fee_escalation {
            if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
                return Err(MempoolError::DuplicateNonce { address, nonce });
            };

            return Ok(None);
        }

        let Some(existing_tx_reference) = self.tx_pool.get_by_address_and_nonce(address, nonce)
        else {
            // Replacement irrelevant: no existing transaction with the same nonce for address.
            return Ok(None);
        };

        if !self.should_replace_tx(&existing_tx_reference, &incoming_tx_reference) {
            info!(
                "{existing_tx_reference} was not replaced by {incoming_tx_reference} due to \
                 insufficient fee escalation."
            );
            // TODO(Elin): consider adding a more specific error type / message.
            return Err(MempoolError::DuplicateNonce { address, nonce });
        }

        Ok(Some(existing_tx_reference))
```
