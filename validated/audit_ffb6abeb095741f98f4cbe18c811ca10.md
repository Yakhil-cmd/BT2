### Title
Gateway `skip_stateful_validations` admits invoke transactions with forged signatures when a pending `deploy_account` exists in the mempool — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function unconditionally skips the `__validate__` entry-point (signature check) for any `Invoke` transaction with `nonce == 1` whenever `account_nonce == 0` and `account_tx_in_pool_or_recent_block` returns `true`. An attacker who observes a legitimate `deploy_account` transaction in the mempool can immediately submit a crafted `Invoke` with `nonce = 1` carrying an arbitrary/forged signature for the same sender address. The gateway admits this transaction into the mempool without ever running the account's `__validate__` function.

### Finding Description

The relevant code path is:

```
extract_state_nonce_and_run_validations
  └─ run_pre_validation_checks
       ├─ validate_state_preconditions   (resource bounds + nonce range)
       ├─ validate_by_mempool            (mempool-level checks, no Cairo VM)
       └─ skip_stateful_validations      ← returns true → __validate__ is SKIPPED
  └─ run_validate_entry_point(skip_validate=true)
       └─ ExecutionFlags { validate: false, … }   ← __validate__ never called
```

`skip_stateful_validations` returns `true` when all three conditions hold:

1. Transaction type is `Invoke`
2. `tx.nonce() == Nonce(Felt::ONE)`
3. `account_nonce == Nonce(Felt::ZERO)` **and** `account_tx_in_pool_or_recent_block(sender) == true` [1](#0-0) 

Condition 3 is satisfied the moment any `deploy_account` for the target address lands in the mempool. An attacker watching the mempool can immediately craft an `Invoke` with `nonce = 1`, an arbitrary signature, and resource bounds set to the maximum the victim's freshly-deployed account can afford. Because `validate_by_mempool` performs only mempool-level checks (nonce gap, fee threshold) and does not execute Cairo VM code, the forged transaction passes all gateway checks and is enqueued. [2](#0-1) 

During block production the batcher calls `AccountTransaction::new_for_sequencing`, which always sets `validate: true` and `strict_nonce_check: true`. [3](#0-2) 

So the forged transaction **will** be validated at execution time and will revert. However, the blockifier still charges a fee for the reverted transaction (the `PostExecutionReport` path), and the account's nonce is consumed, invalidating the legitimate `Invoke` with `nonce = 1` that the real owner submitted as part of the same deploy-account + invoke UX flow. [4](#0-3) 

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

- A forged `Invoke` with an invalid signature is admitted to the mempool and included in a block.
- The victim's account nonce is consumed by the attacker's transaction, permanently blocking the legitimate `nonce = 1` invoke from executing.
- The victim's account is charged a fee for a transaction it never signed (bounded by the resource bounds the attacker chose, up to the account's balance).
- The attack requires no privileged access; any observer of the public mempool can execute it.

### Likelihood Explanation

**Medium.** The attacker must race to submit the forged invoke before the victim's own `nonce = 1` invoke is processed. The window is the time between the `deploy_account` appearing in the mempool and the block being sealed. In practice this is several seconds, which is ample time for an automated bot. The attack is cheap (only one transaction) and repeatable for every new account deployment observed in the mempool.

### Recommendation

The `skip_stateful_validations` bypass should not be conditioned solely on `account_tx_in_pool_or_recent_block`. At minimum, the check should be narrowed to verify that the transaction in the pool is specifically a `deploy_account` (not any arbitrary transaction), and the forged invoke's transaction hash should be bound to the specific `deploy_account` hash so that a third party cannot inject a different payload. Alternatively, the gateway should run a lightweight signature-format check (e.g., verify the signature length and that the felt values are in range) even when skipping the full `__validate__` execution, to raise the cost of forging.

### Proof of Concept

1. Alice broadcasts `deploy_account` for address `A` (class `C`, salt `S`). It enters the mempool; `account_nonce(A) == 0`.
2. Attacker observes the mempool. `account_tx_in_pool_or_recent_block(A)` now returns `true`.
3. Attacker constructs `Invoke { sender: A, nonce: 1, calldata: <drain_calldata>, signature: [0x41, 0x41], resource_bounds: MAX }`.
4. Gateway evaluates:
   - `validate_state_preconditions`: nonce `1` is within `[0, 200]` ✓, resource bounds ✓
   - `validate_by_mempool`: nonce gap OK ✓
   - `skip_stateful_validations`: `nonce==1 && account_nonce==0 && in_pool==true` → returns `true`
   - `run_validate_entry_point(skip_validate=true)`: `ExecutionFlags { validate: false }` → `__validate__` **never called**
5. Forged invoke is admitted to the mempool.
6. Block is produced: `deploy_account` executes (Alice's account is live), then the forged invoke executes with `validate: true`. `__validate__` rejects the bogus signature; the invoke reverts; Alice's account is charged a fee and her nonce advances to `2`.
7. Alice's legitimate `nonce = 1` invoke (submitted simultaneously with the deploy) is now rejected from the mempool with `InvalidTransactionNonce` because nonce `1` was already consumed. [5](#0-4) [6](#0-5)

### Citations

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L399-411)
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L147-155)
```rust
    pub fn new_for_sequencing(tx: Transaction) -> Self {
        let execution_flags = ExecutionFlags {
            only_query: false,
            charge_fee: enforce_fee(&tx, false),
            validate: true,
            strict_nonce_check: true,
        };
        AccountTransaction { tx, execution_flags }
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
