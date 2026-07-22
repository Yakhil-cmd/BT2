### Title
Gateway `skip_stateful_validations` Admits Invoke Transactions With Invalid Signatures When a Deploy-Account Is Pending — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's stateful validation path contains a UX shortcut (`skip_stateful_validations`) that completely bypasses the account's `__validate__` entry-point (i.e., signature verification) for any Invoke transaction whose nonce equals 1 and whose sender address appears in the mempool or a recent block. An unprivileged attacker who observes a victim's pending `deploy_account` transaction can submit a competing Invoke with nonce=1, an arbitrary/invalid signature, and a higher tip. The gateway admits the attacker's transaction without ever calling `__validate__`, allowing it to displace the victim's legitimate first Invoke via fee-escalation replacement.

### Finding Description

`skip_stateful_validations` is called inside `run_pre_validation_checks`, which is the gateway-level stateful check executed before a transaction is forwarded to the mempool.

```
extract_state_nonce_and_run_validations
  └─ run_pre_validation_checks
       ├─ validate_state_preconditions   (nonce range, resource bounds)
       ├─ validate_by_mempool            (duplicate/old nonce)
       └─ skip_stateful_validations      ← returns true → __validate__ skipped
```

The function hardcodes the skip condition:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 429-461
async fn skip_stateful_validations(...) -> ... {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
```

When it returns `true`, `run_validate_entry_point` sets `validate: false`:

```rust
// lines 311-312
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

Inside `StatefulValidator::perform_validations` (blockifier), when `validate == false` the `__validate__` call is entirely skipped:

```rust
// crates/blockifier/src/blockifier/stateful_validator.rs  lines 76-94
ApiTransaction::Invoke(_) => {
    tx.perform_pre_validation_stage(self.state(), &tx_context)?;
    if !tx.execution_flags.validate {
        return Ok(());   // ← exits here; __validate__ never called
    }
    let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
    ...
}
```

`perform_pre_validation_stage` still runs nonce and fee-bound checks, but with `strict_nonce_check = false` the nonce check is `account_nonce (0) <= tx_nonce (1)`, which passes. If the victim's address is pre-funded (the normal deploy-account UX requires this), the fee-bound check also passes.

The mempool's `account_tx_in_pool_or_recent_block` returns `true` for any address that has any transaction in the pool or a recently committed block — including the victim's `deploy_account`:

```rust
// crates/apollo_mempool/src/mempool.rs  lines 697-700
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

**Attack steps:**

1. Victim pre-funds their deterministic address and submits `deploy_account` (nonce=0) + `invoke` (nonce=1, tip=T).
2. Attacker observes the victim's `deploy_account` in the mempool (address is public/deterministic).
3. Attacker submits `invoke` (nonce=1, tip=T+1, **arbitrary invalid signature**) from the victim's address.
4. Gateway: `account_nonce=0`, `tx_nonce=1`, `account_tx_in_pool_or_recent_block=true` → `skip_validate=true` → `__validate__` not called → transaction admitted.
5. Mempool fee-escalation: attacker's invoke (higher tip) replaces victim's invoke at nonce=1.
6. Batcher executes: `deploy_account` succeeds; attacker's invoke runs `__validate__` → fails (invalid signature) → reverted.
7. Victim's invoke is gone from the mempool; victim must resubmit.

The attacker can repeat this indefinitely, permanently preventing the victim's first invoke from executing.

Note also that `StatefulTransactionValidatorConfig` carries a `max_nonce_for_validation_skip` field (default `Nonce(Felt::ONE)`) that is never consulted by `skip_stateful_validations`; the function hardcodes `Nonce(Felt::ONE)` directly, making the config field dead code in the gateway path.

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An unprivileged attacker can inject Invoke transactions with completely invalid signatures into the mempool by exploiting the deploy-account UX skip. Via fee-escalation replacement, the attacker can displace a victim's legitimate first Invoke, causing it to be silently dropped. The attacker pays no net cost (the failing transaction is reverted; if the account has no balance the fee charge also fails). The victim must detect the failure and resubmit, and the attack can be repeated indefinitely.

### Likelihood Explanation

The victim's deploy-account address is deterministic and publicly computable from the class hash, salt, and constructor calldata — all of which are visible in the mempool. The attack window is the time between the victim's deploy-account entering the mempool and being committed. No privileged access is required; any user can submit transactions to the gateway.

### Recommendation

1. **Verify the sender's signature even when skipping `__validate__`**: perform a lightweight ECDSA check on the transaction hash before admitting the transaction, independent of whether the account contract exists.
2. **Alternatively, restrict the skip to transactions whose sender address matches the deploy-account address in the same mempool batch**, so only the legitimate owner of the pending deploy-account can benefit from the skip.
3. **Wire `max_nonce_for_validation_skip` from `StatefulTransactionValidatorConfig` into `skip_stateful_validations`** so the skip threshold is configurable and consistent with the `PyValidator` path.

### Proof of Concept

```
// Precondition: victim pre-funds address A (deterministic from deploy_account params).
// Victim submits:
//   TX1: deploy_account { sender: A, nonce: 0, signature: valid }
//   TX2: invoke        { sender: A, nonce: 1, tip: 10, signature: valid }

// Attacker observes TX1 in mempool (A is public).
// Attacker submits:
//   TX3: invoke { sender: A, nonce: 1, tip: 11, signature: [0xff, 0xff, ...] }

// Gateway path for TX3:
//   get_nonce_from_state(A) → 0          (account not yet deployed)
//   validate_nonce: 0 <= 1 <= 200        → OK
//   validate_by_mempool: nonce=1 exists  → fee-escalation check (tip 11 > 10) → OK
//   skip_stateful_validations:
//     tx.nonce()==1 && account_nonce==0  → true
//     account_tx_in_pool_or_recent_block(A) → true (TX1 is in pool)
//     returns true  →  skip_validate = true
//   run_validate_entry_point: validate=false → __validate__ NOT called
//   TX3 admitted to mempool, replaces TX2 (higher tip).

// Batcher executes TX1 (deploy_account) → A deployed, nonce=1.
// Batcher executes TX3 (attacker's invoke, nonce=1):
//   __validate__ called → invalid signature → REVERT.
// TX2 (victim's invoke) is gone from mempool.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_gateway_config/src/config.rs (L276-300)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, Validate, PartialEq)]
pub struct StatefulTransactionValidatorConfig {
    // If true, ensures the max L2 gas price exceeds (a configurable percentage of) the base gas
    // price of the previous block.
    pub validate_resource_bounds: bool,
    pub max_allowed_nonce_gap: u32,
    pub reject_future_declare_txs: bool,
    pub max_nonce_for_validation_skip: Nonce,
    pub versioned_constants_overrides: Option<VersionedConstantsOverrides>,
    // Minimum gas price as percentage of threshold to accept transactions.
    pub min_gas_price_percentage: u8, // E.g., 80 to require 80% of threshold.
}

impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
            min_gas_price_percentage: 100,
            versioned_constants_overrides: None,
        }
    }
}
```
