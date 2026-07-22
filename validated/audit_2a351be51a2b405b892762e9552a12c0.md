### Title
Permissionless Signature-Skip Admission: Any Caller Can Inject Unsigned Invoke Transactions for Any Account with a Pending `deploy_account` — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`skip_stateful_validations()` in the Apollo Gateway's stateful validator skips the `__validate__` entry-point (signature verification) for any invoke transaction whose sender has nonce=0 in state and nonce=1 in the transaction, provided `account_tx_in_pool_or_recent_block` returns `true` for that sender address. The check only confirms that *some* transaction for the target address exists in the mempool — it does not verify that the incoming invoke transaction is signed by the account owner. Any unprivileged attacker who observes a victim's `deploy_account` transaction in the mempool can immediately submit a crafted invoke transaction for the victim's address with an arbitrary or empty signature, and the gateway will admit it into the mempool without any signature check.

### Finding Description

The vulnerable path is:

**Step 1 — `skip_stateful_validations` decides to skip `__validate__`:** [1](#0-0) 

The function returns `true` (skip validation) when:
- The transaction is an `Invoke`
- `tx.nonce() == Nonce(Felt::ONE)`
- `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed)
- `account_tx_in_pool_or_recent_block(sender_address)` returns `true`

The last condition only checks whether *any* transaction for the sender address is in the mempool or a recent block. It does **not** verify that the incoming invoke transaction carries a valid signature from the account owner.

**Step 2 — `run_validate_entry_point` propagates the skip:** [2](#0-1) 

When `skip_validate = true`, `execution_flags.validate` is set to `false`, and the blockifier's `StatefulValidator::perform_validations` short-circuits before calling `__validate__`: [3](#0-2) 

The `__validate__` entry point — which is the sole mechanism for signature verification in Starknet account abstraction — is never called.

**Step 3 — The gateway returns the account nonce and the transaction is forwarded to the mempool:** [4](#0-3) 

The transaction is admitted into the mempool with no signature check performed.

### Impact Explanation

An attacker who observes a victim's `deploy_account` transaction in the public mempool can immediately submit an invoke transaction for the victim's address (nonce=1, arbitrary calldata, arbitrary or empty signature). The gateway will:

1. Confirm `account_nonce == 0` (victim not yet deployed — true by construction).
2. Confirm `account_tx_in_pool_or_recent_block(victim_address) == true` (the victim's own `deploy_account` tx satisfies this).
3. Skip `__validate__` entirely.
4. Admit the attacker's transaction into the mempool.

The attacker's transaction occupies the nonce=1 slot for the victim's account. The victim's own legitimate invoke transaction (also nonce=1) may be rejected as a duplicate or displaced by a higher-fee attacker transaction. When the batcher executes the block, the attacker's transaction will fail at `__validate__` (invalid signature), but the nonce slot has been consumed in the mempool queue, delaying or permanently displacing the victim's first post-deploy invoke transaction.

This matches: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

The precondition is simply that a victim has submitted a `deploy_account` transaction that is visible in the mempool (standard public mempool behavior). No privileged access, no leaked keys, and no special infrastructure are required. Any attacker monitoring the mempool can trigger this for every new account deployment.

### Recommendation

The authorization invariant must be enforced even when the account contract does not yet exist. Two complementary fixes:

1. **Stateless signature pre-check**: Before skipping `__validate__`, verify that the invoke transaction's signature is consistent with the public key embedded in the corresponding `deploy_account` transaction's constructor calldata. This is possible because the `deploy_account` transaction is already in the mempool and its constructor arguments are known.

2. **Tighten the mempool existence check**: `account_tx_in_pool_or_recent_block` should specifically confirm that a `deploy_account` transaction (not just any transaction) exists for the address, and optionally cross-check that the invoke transaction's signature matches the deploying key.

A minimal guard analogous to the Solidity recommendation in the external report:

```rust
// In skip_stateful_validations, before returning true:
if !signature_matches_deploy_account_pubkey(tx, &deploy_account_tx) {
    return Ok(false); // force full __validate__ (which will fail gracefully)
}
```

### Proof of Concept

1. Victim generates a new account keypair; computes `victim_address` from `(class_hash, salt, constructor_calldata)`.
2. Victim submits `deploy_account` tx (nonce=0, signed with victim's private key) to the gateway. It enters the mempool.
3. Attacker observes `victim_address` in the mempool via any public RPC.
4. Attacker constructs an invoke tx: `sender_address = victim_address`, `nonce = 1`, arbitrary `calldata`, **signature = [0x0, 0x0]** (or any bytes).
5. Attacker submits the invoke tx to the gateway.
6. Gateway executes `skip_stateful_validations`:
   - `tx.nonce() == 1` ✓
   - `account_nonce == 0` ✓ (victim not deployed)
   - `account_tx_in_pool_or_recent_block(victim_address)` → `true` ✓ (victim's own deploy_account is there)
   - Returns `true` → `execution_flags.validate = false`
7. `__validate__` is never called. The attacker's transaction is admitted to the mempool.
8. The victim's legitimate invoke tx (nonce=1) is now competing with or displaced by the attacker's invalid tx in the nonce=1 slot.
9. At block execution time, the attacker's tx fails `__validate__` (wrong signature), but the victim's first post-deploy action has been griefed. [5](#0-4) [1](#0-0)

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
