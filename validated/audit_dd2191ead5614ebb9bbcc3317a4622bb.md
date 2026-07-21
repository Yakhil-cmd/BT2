### Title
Invoke Transaction with Nonce=1 Bypasses `__validate__` Signature Verification at Gateway When Deploy-Account Is Pending - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The gateway's `skip_stateful_validations` function unconditionally skips the `__validate__` entry point (signature verification) for any Invoke transaction with `nonce=1` submitted to an account whose on-chain nonce is `0` and which has any transaction in the mempool or a recent block. An unprivileged attacker who observes a victim's pending `deploy_account` transaction can submit a crafted Invoke with an arbitrary or wrong signature for the victim's address, have it admitted to the mempool without signature verification, and thereby displace the victim's legitimate nonce-1 Invoke or force the victim's account to pay validation-phase fees for the attacker's reverted transaction.

### Finding Description

**Root cause — `skip_stateful_validations` returns `true` for any attacker-controlled Invoke**

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` (lines 429–461) returns `true` (meaning: skip `__validate__`) when all three conditions hold:

1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)` (hardcoded).
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed on-chain).
4. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [1](#0-0) 

Condition 4 only checks whether *any* transaction for the sender address exists in the mempool — not that it is a `deploy_account`, not that it was submitted by the same user, and not that the Invoke's signature is valid.

**How the skip propagates to suppress `__validate__`**

`run_pre_validation_checks` calls `skip_stateful_validations` and returns the boolean to `extract_state_nonce_and_run_validations`, which passes it to `run_validate_entry_point`: [2](#0-1) 

Inside `run_validate_entry_point`, `skip_validate = true` is translated directly into `validate: false` on the `ExecutionFlags`: [3](#0-2) 

`StatefulValidator::perform_validations` then returns `Ok(())` immediately after `perform_pre_validation_stage` without ever calling `validate_tx` (the `__validate__` entry point): [4](#0-3) 

`perform_pre_validation_stage` checks nonce, fee bounds, and balance — but **not** the account's signature: [5](#0-4) 

The mempool's `validate_tx` (called earlier in `validate_by_mempool`) also checks only nonce validity and fee escalation — no signature: [6](#0-5) 

**End-to-end exploit path**

1. Victim pre-funds account address `A` (balance > 0) and submits a `deploy_account` transaction (nonce=0). It enters the mempool.
2. Attacker observes the pending `deploy_account` (visible in the mempool or via RPC).
3. Attacker constructs an `Invoke` transaction: `sender_address = A`, `nonce = 1`, arbitrary/wrong signature, resource bounds sufficient to pass `check_fee_bounds` and `verify_can_pay_committed_bounds` against `A`'s pre-funded balance.
4. Gateway stateless validation passes (signature length is syntactically valid). Nonce check in `validate_nonce` passes (`0 ≤ 1 ≤ 0 + max_gap`). `validate_by_mempool` passes (no existing nonce-1 tx). `skip_stateful_validations` returns `true` because `account_tx_in_pool_or_recent_block(A)` is `true`. `run_validate_entry_point` runs with `validate = false` — `__validate__` is never called.
5. Attacker's malicious Invoke is admitted to the mempool with nonce=1.
6. Victim submits their legitimate Invoke (nonce=1). The mempool detects a duplicate nonce and either rejects it or demands fee escalation to replace the attacker's transaction.
7. If the attacker's transaction reaches the batcher: `deploy_account` executes first (deploys `A`), then the malicious Invoke executes — `__validate__` is now called, signature fails, transaction reverts, and validation-phase gas fees are charged from `A`'s balance.

### Impact Explanation

**Admission impact (High):** An unprivileged attacker can inject a transaction with an invalid/forged signature into the mempool for any account that has a pending `deploy_account`. This directly satisfies: *"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."*

**Economic impact:** When the batcher executes the malicious Invoke, the victim's account is charged validation-phase fees for a transaction the victim never authorized. The attacker pays nothing (the transaction is submitted under the victim's address).

**DoS impact:** The victim's legitimate nonce-1 Invoke is blocked or forced to pay a fee-escalation premium to displace the attacker's transaction.

### Likelihood Explanation

The preconditions are observable and common: any user deploying a new account pre-funds it and submits `deploy_account` before the first Invoke. The mempool is queryable. The attack requires no privileged access, no cryptographic break, and no special tooling beyond a standard RPC client.

### Recommendation

The `skip_stateful_validations` logic should not be the sole gate for bypassing `__validate__`. At minimum:

1. Restrict the skip to transactions submitted in the **same gateway request** as the `deploy_account` (i.e., a paired submission), rather than any Invoke that arrives while a `deploy_account` is pending in the mempool.
2. Alternatively, verify the signature against the **expected class hash** declared in the pending `deploy_account` transaction, so that even skipped-validation Invokes are bound to the correct signer.
3. If the skip must remain, add a post-admission check: when the `deploy_account` is committed, re-validate the signature of any nonce-1 Invoke that was admitted under the skip path, and evict it from the mempool if the signature is invalid.

### Proof of Concept

```
# Step 1: Victim pre-funds address A and submits deploy_account (nonce=0).
POST /gateway/add_transaction  { deploy_account, sender=A, nonce=0, valid_sig }
# → admitted; mempool now has tx for address A

# Step 2: Attacker submits malicious Invoke for A with wrong signature.
POST /gateway/add_transaction  { invoke, sender=A, nonce=1, sig=[0xdead, 0xbeef] }
# Gateway flow:
#   validate_nonce: 0 <= 1 <= 200  → OK
#   validate_by_mempool: no nonce-1 tx yet → OK
#   skip_stateful_validations:
#     tx.nonce()==1 && account_nonce==0 && account_tx_in_pool_or_recent_block(A)==true
#     → returns true (skip __validate__)
#   run_validate_entry_point(skip_validate=true):
#     ExecutionFlags { validate: false, ... }
#     perform_pre_validation_stage: nonce OK, balance OK
#     returns Ok(()) without calling __validate__
# → malicious Invoke admitted to mempool

# Step 3: Victim submits legitimate Invoke (nonce=1).
POST /gateway/add_transaction  { invoke, sender=A, nonce=1, valid_sig }
# → mempool rejects with DuplicateNonce or demands fee escalation

# Step 4 (batcher): deploy_account executes, then malicious Invoke executes.
#   __validate__ called → signature fails → Invoke reverted
#   Validation-phase fee charged from A's balance (victim pays)
``` [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L175-178)
```rust
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-356)
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

        // Build block context.
        let mut versioned_constants = VersionedConstants::get_versioned_constants(
            self.config.versioned_constants_overrides.clone(),
        );
        // The validation of a transaction is not affected by the casm hash migration.
        versioned_constants.disable_casm_hash_migration();

        let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        block_info.block_number = block_info.block_number.unchecked_next();
        let block_context = BlockContext::new(
            block_info,
            self.chain_info.clone(),
            versioned_constants,
            BouncerConfig::max(),
        );

        // Move state into the blocking task and run CPU-heavy validation.
        let state_reader_and_contract_manager = self.take_state_reader_and_contract_manager();

        let cur_span = Span::current();
        #[allow(clippy::result_large_err)]
        tokio::task::spawn_blocking(move || {
            cur_span.in_scope(|| {
                let state = CachedState::new(state_reader_and_contract_manager);
                let mut blockifier_validator = StatefulValidator::create(state, block_context);
                blockifier_validator.validate(account_tx)
            })
        })
        .await
        .map_err(|e| StarknetError {
            code: StarknetErrorCode::UnknownErrorCode(
                "StarknetErrorCode.InternalError".to_string(),
            ),
            message: format!("Blocking task join error when running the validate entry point: {e}"),
        })?
        .map_err(|e| StarknetError {
            code: StarknetErrorCode::KnownErrorCode(KnownStarknetErrorCode::ValidateFailure),
            message: e.to_string(),
        })?;
        Ok(())
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

**File:** crates/apollo_mempool/src/mempool.rs (L402-408)
```rust
    pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
        let tx_reference = (&args).into();
        self.validate_incoming_tx(tx_reference, args.account_nonce)?;
        self.validate_fee_escalation(tx_reference)?;

        Ok(())
    }
```
