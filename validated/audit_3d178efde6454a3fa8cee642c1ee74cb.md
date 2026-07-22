### Title
Gateway Admits Invoke Transactions with Arbitrary Signatures via `skip_stateful_validations` — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry-point call (the only place where the account contract verifies the transaction signature) for any invoke transaction with `nonce == 1` when the on-chain account nonce is `0` and `account_tx_in_pool_or_recent_block` returns `true`. Because `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction from that address in the pool — not specifically a `deploy_account` — an unprivileged attacker who observes a victim's pending `deploy_account` can immediately submit a second invoke transaction with `nonce=1` carrying a completely invalid (e.g., all-zero) signature. The gateway admits it to the mempool without any signature check. The victim's own legitimate `nonce=1` invoke is then rejected as `DuplicateNonce`, preventing the intended deploy-and-invoke atomic UX from working correctly.

---

### Finding Description

**Relevant code path** (`extract_state_nonce_and_run_validations` → `run_pre_validation_checks` → `skip_stateful_validations`):

```
crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 158-179
crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 399-410
crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 429-461
crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 302-355
```

The full admission flow is:

1. `extract_state_nonce_and_run_validations` reads the on-chain nonce for the sender, calls `run_pre_validation_checks`, and then calls `run_validate_entry_point` with the boolean `skip_validate` returned by the pre-check. [1](#0-0) 

2. `run_pre_validation_checks` calls `validate_state_preconditions` (nonce range + resource bounds), `validate_by_mempool` (duplicate-hash / nonce-too-old), and finally `skip_stateful_validations`. [2](#0-1) 

3. `skip_stateful_validations` returns `true` — meaning **skip the `__validate__` call** — when all three conditions hold:
   - The transaction is an `Invoke`
   - `tx.nonce() == Nonce(Felt::ONE)`
   - `account_nonce == Nonce(Felt::ZERO)`
   - `account_tx_in_pool_or_recent_block(sender_address)` returns `true` [3](#0-2) 

4. When `skip_validate == true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags` and returns immediately after `perform_pre_validation_stage` without ever calling the account contract's `__validate__` entry point. [4](#0-3) 

**The broken assumption**: The code comment states *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* This is incorrect. `account_tx_in_pool_or_recent_block` returns `true` whenever the account has **any** transaction in the pool or is known from a recent committed block:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [5](#0-4) 

It does **not** verify that the pooled transaction is specifically a `deploy_account`. An attacker who submits a `deploy_account` for their own address (which passes full validation) causes `account_tx_in_pool_or_recent_block` to return `true` for that address. But more critically, the victim's own `deploy_account` in the pool is visible to anyone, and the attacker can use it to trigger the skip for the victim's address.

**`validate_by_mempool` does not compensate**: `Mempool::validate_tx` only checks for duplicate tx-hash and nonce-too-old / duplicate-nonce conditions; it performs no signature verification. [6](#0-5) 

**`max_nonce_for_validation_skip` is `Nonce(Felt::ONE)` in production config**, so the window is exactly nonce=1, but that is precisely the nonce of the first post-deploy invoke — the most security-sensitive transaction in the deploy-and-invoke UX flow. [7](#0-6) 

---

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions and rejects valid transactions before sequencing.**

1. **Invalid transaction admitted**: An invoke transaction with a completely invalid signature (e.g., `[0, 0]`) for a victim's account is accepted by the gateway and inserted into the mempool without any signature check.

2. **Victim's legitimate transaction rejected**: When the victim subsequently submits their real `nonce=1` invoke, the mempool rejects it with `MempoolError::DuplicateNonce` (or requires fee escalation to displace the attacker's transaction). [8](#0-7) 

3. **Block-level consequence**: The attacker's invalid transaction will be included in a block, execute `__validate__`, fail (signature invalid), and be reverted — consuming block resources and delaying the victim's deploy-and-invoke sequence by at least one block.

4. **Denial of the UX guarantee**: The entire purpose of `skip_stateful_validations` is to allow a user to submit `deploy_account + invoke(nonce=1)` atomically. The attacker nullifies this guarantee for any victim whose `deploy_account` is visible in the mempool.

---

### Likelihood Explanation

- **Unprivileged trigger**: Any external observer can read the mempool (P2P propagation, RPC `starknet_pendingTransactions`, or simply watching the gateway). No special access is required.
- **Narrow but deterministic window**: The condition `nonce=1 && account_nonce=0` is exactly the state every new account is in between submitting `deploy_account` and having it executed. Every new account deployment opens this window.
- **Low cost**: The attacker only needs to submit one transaction with a valid-format but invalid-content signature. No funds are required beyond the minimum resource bounds (which are also not enforced for signature correctness).

---

### Recommendation

1. **Verify the pooled transaction type**: Change `account_tx_in_pool_or_recent_block` to `deploy_account_in_pool_or_recent_block` — a query that returns `true` only when the account's pooled transaction at nonce=0 is specifically a `DeployAccount`. This matches the intent stated in the comment.

2. **Alternatively, follow the `py_validator` pattern**: `PyValidator::should_run_stateful_validations` requires the caller to explicitly pass `deploy_account_tx_hash: Option<TransactionHash>` and only skips validation when that hash is `Some` and the on-chain nonce is still zero. This is a stronger guarantee because the caller must have already validated the deploy_account hash. [9](#0-8) 

3. **Minimum fix**: Inside `skip_stateful_validations`, after `account_tx_in_pool_or_recent_block` returns `true`, additionally query the mempool to confirm that the pooled transaction for `(sender_address, nonce=0)` is a `DeployAccount` type before returning `true`.

---

### Proof of Concept

```
Precondition: victim V has submitted deploy_account(nonce=0) for address A.
              The deploy_account is in the mempool.
              On-chain nonce for A is 0.

Step 1 – Attacker queries mempool/P2P and learns address A.

Step 2 – Attacker constructs:
    InvokeTransactionV3 {
        sender_address: A,
        nonce: 1,
        signature: [Felt::ZERO, Felt::ZERO],   // completely invalid
        calldata: [<any>],
        resource_bounds: <minimum valid bounds>,
        ...
    }

Step 3 – Attacker submits to gateway.

Step 4 – Gateway stateful validation:
    account_nonce = get_nonce(A) = 0
    validate_state_preconditions:
        validate_nonce: 0 <= 1 <= 200  → OK
        validate_resource_bounds:       → OK
    validate_by_mempool:
        no duplicate hash, nonce 1 not yet in pool → OK
    skip_stateful_validations:
        tx.nonce() == 1                 → true
        account_nonce == 0              → true
        account_tx_in_pool_or_recent_block(A)
            = tx_pool.contains_account(A)  // deploy_account(nonce=0) is there
            = true                      → true
        → returns true  (SKIP __validate__)
    run_validate_entry_point(skip_validate=true):
        execution_flags.validate = false
        → __validate__ is NEVER called
        → signature [0,0] is NEVER checked
        → transaction ADMITTED to mempool

Step 5 – Victim submits their real invoke(nonce=1, valid_signature).
    validate_by_mempool:
        tx_pool already has (A, nonce=1) from attacker
        → MempoolError::DuplicateNonce  → REJECTED

Step 6 – Attacker's invalid transaction is eventually executed in a block:
    blockifier calls __validate__ → signature check fails → transaction reverted
    Victim's deploy_account executes successfully but their invoke is gone.
    Victim must resubmit invoke in the next block.
```

The root cause is at: [10](#0-9)

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

**File:** crates/apollo_mempool/src/mempool.rs (L757-792)
```rust
    /// `(address, nonce)` via fee escalation, without mutating any state. Returns the existing
    /// transaction to be replaced when a valid replacement exists, `None` when there is nothing to
    /// replace, or an error when a replacement is present but not permitted.
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
    }
```

**File:** crates/apollo_gateway_config/src/config.rs (L289-299)
```rust
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
```

**File:** crates/native_blockifier/src/py_validator.rs (L98-121)
```rust
    pub fn should_run_stateful_validations(
        &mut self,
        account_tx: &AccountTransaction,
        deploy_account_tx_hash: Option<TransactionHash>,
    ) -> StatefulValidatorResult<bool> {
        if account_tx.tx_type() != TransactionType::InvokeFunction {
            return Ok(true);
        }
        let tx_info = account_tx.create_tx_info();
        let nonce = self.stateful_validator.get_nonce(tx_info.sender_address())?;

        let deploy_account_not_processed =
            deploy_account_tx_hash.is_some() && nonce == Nonce(Felt::ZERO);
        let tx_nonce = tx_info.nonce();
        let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;

        Ok(!skip_validate)
    }
```
