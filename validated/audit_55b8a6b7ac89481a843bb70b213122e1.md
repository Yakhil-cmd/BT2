### Title
Gateway Skips Account Signature Validation for Invoke Transactions on Undeployed Accounts, Enabling Mempool Injection of Unsigned Transactions — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally bypasses the `__validate__` entry-point call (which verifies the account's signature) for any Invoke V3 transaction with `nonce == 1` targeting an account whose on-chain nonce is still `0` and which has any transaction in the mempool. An unprivileged attacker who observes a victim's `deploy_account` transaction in the mempool can submit a replacement Invoke transaction with an arbitrary (or absent) signature and a marginally higher fee. The gateway admits it without signature verification, the mempool's fee-escalation logic replaces the victim's legitimate Invoke, and the attacker's unsigned transaction is later executed and reverts — permanently evicting the victim's Invoke from the mempool.

### Finding Description

`skip_stateful_validations` is called inside `run_pre_validation_checks` after `validate_by_mempool` but before `run_validate_entry_point`: [1](#0-0) 

When the three conditions below are all true, it returns `true` (skip): [2](#0-1) 

The returned boolean is then used to set `execution_flags.validate = false`: [3](#0-2) 

With `validate = false`, `StatefulValidator::perform_validations` returns immediately after `perform_pre_validation_stage` without ever calling `validate_tx` (the `__validate__` entry point): [4](#0-3) 

`perform_pre_validation_stage` only checks nonce, fee bounds, and proof facts — it never touches the signature: [5](#0-4) 

The transaction hash does not commit to the signature field (signature is verified only by `__validate__`), so a transaction with a completely different or empty signature produces a distinct `tx_hash` and passes all hash-based deduplication checks: [6](#0-5) 

The mempool's `validate_tx` path checks only nonce ordering and fee-escalation rules, not signatures: [7](#0-6) 

Fee escalation is supported and allows a higher-fee transaction to replace an existing one at the same nonce for the same address.

**Attack flow:**

1. Victim broadcasts `deploy_account` (nonce 0) + `invoke` (nonce 1, fee F, valid signature).
2. Both land in the mempool; `account_tx_in_pool_or_recent_block` returns `true` for the victim's address.
3. Attacker submits `invoke` (nonce 1, fee F+1, **invalid/empty signature**, arbitrary calldata) for the victim's address.
4. Gateway stateless check passes (signature length ≤ max).
5. `validate_nonce`: `0 ≤ 1 ≤ max_allowed_nonce_gap` — passes.
6. `validate_by_mempool`: fee-escalation check passes (higher fee).
7. `skip_stateful_validations`: nonce=1, account_nonce=0, account in mempool → returns `true`.
8. `run_validate_entry_point` with `validate=false` — `__validate__` is **never called**.
9. Attacker's transaction is admitted; mempool replaces victim's invoke with attacker's.
10. `deploy_account` executes; attacker's invoke runs `__validate__`, fails (bad signature), reverts.
11. Victim's invoke is permanently gone from the mempool.

### Impact Explanation

An invalid transaction — one whose account signature has never been verified — is accepted by the gateway and inserted into the mempool, satisfying the **High** impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."* The victim's legitimate Invoke is evicted and must be resubmitted; if the attacker repeats the attack, the victim's post-deploy Invoke can be permanently suppressed. At scale, an attacker can flood the mempool with unsigned transactions targeting all newly-deploying accounts, degrading liveness for new users.

### Likelihood Explanation

The conditions are easy to satisfy: the attacker only needs to watch the public mempool (or P2P gossip) for `deploy_account` transactions, then submit a replacement Invoke with a slightly higher fee. No privileged access, no special knowledge of the victim's private key, and no on-chain state is required. The `skip_stateful_validations` path is always active when `allow_client_side_proving` is irrelevant and the UX feature is enabled.

### Recommendation

The skip-validate path was introduced to allow the UX pattern of sending `deploy_account + invoke` atomically. However, it must not admit transactions whose signatures have never been checked. Two mitigations:

1. **Bind the skip to the exact transaction hash**: when the deploy_account is submitted, record the paired invoke's `tx_hash`. Only skip `__validate__` for the invoke whose hash matches the recorded one. Any replacement attempt with a different hash must go through full validation (which will fail because the account does not yet exist, and that is the correct rejection).

2. **Alternatively, defer signature verification to execution time but mark the transaction as "unvalidated"**: the batcher must then treat such transactions as requiring `__validate__` at execution time and must not allow fee-escalation replacement of an unvalidated transaction by another unvalidated transaction.

### Proof of Concept

```
# Precondition: victim's deploy_account (nonce=0) is in the mempool for address A.
# Victim's invoke: nonce=1, fee=100, valid_sig, calldata=[victim_call]

# Attacker submits:
POST /gateway/add_transaction
{
  "type": "INVOKE_FUNCTION",
  "version": "0x3",
  "sender_address": A,          # victim's address
  "nonce": "0x1",
  "calldata": ["0xdeadbeef"],   # arbitrary
  "signature": [],              # empty — never verified
  "resource_bounds": {
    "l2_gas": { "max_amount": "0x1000", "max_price_per_unit": "0x65" }  # fee > 100
  },
  ...
}

# Gateway path:
# 1. stateless_tx_validator.validate() → OK (empty sig within max_signature_length)
# 2. convert_rpc_tx_to_internal() → tx_hash_attacker ≠ tx_hash_victim
# 3. extract_state_nonce_and_run_validations():
#    - account_nonce = 0  (A not yet deployed)
#    - validate_nonce(nonce=1, account_nonce=0) → OK (within gap)
#    - validate_by_mempool() → fee escalation passes (higher fee)
#    - skip_stateful_validations() → TRUE  ← signature check bypassed
#    - run_validate_entry_point(skip=true) → returns immediately
# 4. mempool.add_tx() → replaces victim's invoke with attacker's

# Result: victim's invoke is evicted; attacker's unsigned tx is in the mempool.
# At execution: __validate__ is called, fails (empty sig), tx reverts.
``` [8](#0-7)

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L353-372)
```rust
    // Performs static checks before executing validation entry point.
    // Note that nonce is incremented during these checks.
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

**File:** crates/starknet_api/src/transaction_hash.rs (L388-404)
```rust
    let mut hash_chain = HashChain::new()
        .chain(&INVOKE)
        .chain(&transaction_version.0)
        .chain(transaction.sender_address().0.key())
        .chain(&tip_resource_bounds_hash)
        .chain(&paymaster_data_hash)
        .chain(&Felt::try_from(chain_id)?)
        .chain(&transaction.nonce().0)
        .chain(&data_availability_mode)
        .chain(&account_deployment_data_hash)
        .chain(&calldata_hash);
    if !transaction.proof_facts().0.is_empty() {
        let proof_facts_hash =
            HashChain::new().chain_iter(transaction.proof_facts().0.iter()).get_poseidon_hash();
        hash_chain = hash_chain.chain(&proof_facts_hash);
    }
    Ok(TransactionHash(hash_chain.get_poseidon_hash()))
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
