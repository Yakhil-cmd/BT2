### Title
Gateway `skip_stateful_validations` Admits Invoke Transactions with Invalid Signatures by Front-Running the Deploy-Account UX Skip — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry point (the only place where the account signature is verified) for invoke transactions with nonce=1 when the target account has any transaction in the mempool. An unprivileged attacker who observes a `deploy_account` transaction in the mempool can front-run the legitimate user's paired invoke by submitting an invoke with nonce=1 and an **invalid/arbitrary signature** from the same address. The gateway admits this transaction without ever verifying the signature, violating the invariant that all mempool-admitted invoke transactions carry a valid account signature.

---

### Finding Description

The gateway stateful validation path in `extract_state_nonce_and_run_validations` fetches the on-chain nonce, runs pre-validation checks, and then conditionally skips the blockifier `__validate__` call:

```
extract_state_nonce_and_run_validations
  └─ run_pre_validation_checks
       ├─ validate_state_preconditions   (nonce range, gas price — no signature)
       ├─ validate_by_mempool            (duplicate hash/nonce, fee escalation — no signature)
       └─ skip_stateful_validations      ← returns true → __validate__ is SKIPPED
  └─ run_validate_entry_point(skip_validate=true)
       └─ StatefulValidator::perform_validations with execution_flags.validate = false
            └─ returns Ok(()) before calling __validate__
```

The `skip_stateful_validations` function returns `true` (skip) when all three conditions hold: [1](#0-0) 

1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)` — the tx carries nonce 1.
3. `account_nonce == Nonce(Felt::ZERO)` — the account is not yet deployed on-chain.
4. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`.

The comment in the code acknowledges the intent: "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." However, `account_tx_in_pool_or_recent_block` checks whether **any** transaction from that address is known to the mempool state — it does not verify that the existing transaction is a `deploy_account` or that it was submitted by the same party: [2](#0-1) 

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [3](#0-2) 

Inside `StatefulValidator::perform_validations`, an invoke transaction with `validate = false` returns `Ok(())` immediately after `perform_pre_validation_stage`, never reaching the `__validate__` call: [4](#0-3) 

`perform_pre_validation_stage` checks nonce, fee bounds, and proof facts — but **not the signature**: [5](#0-4) 

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks for duplicate tx hash, nonce range, and fee escalation — no signature: [6](#0-5) [7](#0-6) 

`ValidationArgs` carries no signature field; the mempool never sees or checks it.

---

### Impact Explanation

An attacker can submit an invoke transaction carrying an **arbitrary/invalid signature** that is admitted to the mempool without any signature verification. This breaks the admission invariant: every invoke transaction in the mempool is supposed to have passed `__validate__`. Concretely:

- The attacker's invalid invoke occupies the nonce=1 slot for the victim's address.
- The victim's legitimate invoke (nonce=1) is subsequently rejected by the mempool with `DuplicateNonce` (when fee escalation is disabled) or forced to pay a higher tip to replace it (when fee escalation is enabled).
- When the batcher executes the attacker's invalid invoke, it reverts (signature fails at execution time), but the victim's deploy_account has already been consumed and the intended invoke never executes.

This matches the **High** impact scope: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

---

### Likelihood Explanation

The mempool is observable (transactions are broadcast over P2P). Any attacker can watch for `deploy_account` transactions, extract the target contract address, and immediately submit a competing invoke with nonce=1 and a garbage signature. No privileged access, no special knowledge, and no cryptographic capability is required. The race window is the time between the victim's `deploy_account` being admitted and the victim's invoke being submitted — a window that is explicitly widened by the UX feature itself (users are expected to submit both transactions together, meaning the deploy_account will be in the mempool for at least one network round-trip before the invoke arrives).

---

### Recommendation

**Short term:** In `skip_stateful_validations`, replace the generic `account_tx_in_pool_or_recent_block` check with a check that specifically confirms a `deploy_account` transaction for the address is present in the mempool (e.g., expose a `deploy_account_in_pool(address)` query). This ensures the skip only fires when the legitimate deployer's own `deploy_account` is pending, not when any arbitrary transaction from that address is known.

**Long term:** Consider running a lightweight signature pre-check (e.g., ECDSA verification on the raw felt array) at the gateway level before admitting any invoke to the mempool, independent of the `__validate__` skip. Alternatively, bind the skip to the specific `tx_hash` of the paired `deploy_account` transaction so that only the submitter of the deploy can benefit from the skip.

---

### Proof of Concept

```
1. Alice submits deploy_account for address X (class_hash=C, salt=S, nonce=0).
   → Gateway admits it; mempool now knows address X.

2. Attacker observes Alice's deploy_account in the mempool (P2P broadcast).

3. Attacker constructs invoke(sender=X, nonce=1, calldata=[steal_funds], signature=[0xdead, 0xbeef]).

4. Gateway stateful validation:
   - get_nonce_from_state(X) → 0   (X not yet deployed)
   - validate_state_preconditions: nonce 1 ≥ 0 ✓, gas price ✓
   - validate_by_mempool: no existing nonce-1 tx for X ✓
   - skip_stateful_validations:
       tx.nonce()==1 ✓, account_nonce==0 ✓,
       account_tx_in_pool_or_recent_block(X)==true ✓  ← Alice's deploy_account
     → returns true (SKIP __validate__)
   - run_validate_entry_point(skip_validate=true):
       execution_flags.validate = false
       StatefulValidator returns Ok(()) without calling __validate__
   → Attacker's invoke ADMITTED to mempool with invalid signature.

5. Alice submits her legitimate invoke(sender=X, nonce=1, calldata=[intended_action]).
   → Mempool: DuplicateNonce for (X, 1) → REJECTED.

6. Batcher executes block:
   - deploy_account(X) → X deployed, nonce becomes 1.
   - attacker's invoke(X, nonce=1) → __validate__ called → signature fails → REVERTED.
   - Alice's intended invoke never executes.
``` [8](#0-7) [9](#0-8) [10](#0-9)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-355)
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

**File:** crates/apollo_mempool_types/src/mempool_types.rs (L50-57)
```rust
pub struct ValidationArgs {
    pub address: ContractAddress,
    pub account_nonce: Nonce,
    pub tx_hash: TransactionHash,
    pub tx_nonce: Nonce,
    pub tip: Tip,
    pub max_l2_gas_price: GasPrice,
}
```
