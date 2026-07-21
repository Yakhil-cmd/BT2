### Title
`skip_stateful_validations` Admits Unsigned Invoke Transactions for Any Account With a Pending Deploy-Account - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry-point (signature verification) for any invoke transaction with `nonce == 1` when the target account has **any** transaction present in the mempool and the on-chain nonce is zero. Because `account_tx_in_pool_or_recent_block` returns `true` as soon as a victim's `deploy_account` transaction enters the pool, an unprivileged attacker can immediately submit a forged invoke transaction (nonce=1, arbitrary/empty signature) for the victim's address and have it admitted to the mempool without any signature check.

### Finding Description

The gateway stateful validation path is:

```
extract_state_nonce_and_run_validations
  └─ run_pre_validation_checks
       ├─ validate_state_preconditions   (nonce range, resource bounds)
       ├─ validate_by_mempool            (duplicate hash / nonce-too-old only)
       └─ skip_stateful_validations      ← decides whether __validate__ runs
  └─ run_validate_entry_point(skip_validate)
```

`skip_stateful_validations` returns `true` (skip signature verification) when all three conditions hold: [1](#0-0) 

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
}
```

The third condition delegates to: [2](#0-1) 

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

This returns `true` for **any** transaction type in the pool for that address — not specifically a `deploy_account`. The inline comment claims this is safe because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." That reasoning is circular: the very transaction being admitted right now is the first invoke (nonce=1), and it is being admitted *without* validation. No prior validated invoke for this account can exist in the pool because the account has nonce=0 and no deployed code, so any invoke with nonce≥1 would fail `__validate__` — unless it is the one currently exploiting this skip path.

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [3](#0-2) 

and `StatefulValidator::perform_validations` returns `Ok(())` before calling `__validate__`: [4](#0-3) 

The transaction is then forwarded to the mempool with no signature ever verified.

### Impact Explanation

An attacker who observes a victim's `deploy_account` transaction in the mempool can immediately submit a forged invoke transaction (nonce=1, empty or garbage signature, arbitrarily high tip) for the victim's address. The gateway admits it without running `__validate__`. The forged transaction enters the mempool and, because the mempool applies fee-escalation rules, it can displace the victim's legitimate nonce-1 invoke transaction if the attacker bids a higher tip. When the batcher later executes the forged transaction, `__validate__` runs and the transaction is rejected (nonce not incremented). But the victim's legitimate invoke is already gone from the mempool and must be resubmitted. This breaks the deploy-account + invoke atomic UX guarantee and constitutes gateway admission of an invalid (signature-less) transaction.

Matches allowed impact: **High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

### Likelihood Explanation

- The attack requires only monitoring the public mempool for `deploy_account` transactions, which is trivially observable.
- No privileged access, no special keys, and no on-chain state is required.
- The attacker only needs to submit a single forged invoke transaction with a higher tip than the victim's.
- The window is the time between the victim's `deploy_account` entering the mempool and the block being committed — typically seconds to minutes.

### Recommendation

`skip_stateful_validations` must verify that the transaction present in the mempool for the account is specifically a `deploy_account` transaction, not just any transaction. The mempool client should expose a dedicated query such as `has_deploy_account_in_pool(address)` that inspects the transaction type, rather than the generic `account_tx_in_pool_or_recent_block`. Alternatively, the gateway can track the deploy-account tx hash explicitly (as the `native_blockifier` Python path already does via the `deploy_account_tx_hash` parameter in `PyValidator::should_run_stateful_validations`) and only skip validation when that specific hash is present. [5](#0-4) 

### Proof of Concept

1. Victim submits `deploy_account` for address `A` (class_hash `C`, salt `S`). The transaction enters the mempool; `tx_pool.contains_account(A)` becomes `true`.

2. Attacker submits an `RpcInvokeTransaction::V3` with:
   - `sender_address = A`
   - `nonce = 1`
   - `signature = []` (empty)
   - `tip` set higher than the victim's planned invoke tip

3. Gateway stateful validation evaluates `skip_stateful_validations`:
   - `tx.nonce() == Nonce(Felt::ONE)` → ✓
   - `account_nonce == Nonce(Felt::ZERO)` → ✓ (account not yet deployed)
   - `account_tx_in_pool_or_recent_block(A)` → ✓ (deploy_account is in pool)
   - Returns `true` (skip `__validate__`)

4. `run_validate_entry_point` is called with `skip_validate = true`; `execution_flags.validate = false`; `StatefulValidator::perform_validations` returns `Ok(())` without running `__validate__`.

5. The forged invoke is forwarded to the mempool via `add_tx`.

6. Victim submits their legitimate invoke (nonce=1, correct signature, lower tip). The mempool sees a duplicate nonce for address `A`; fee-escalation rules reject the victim's tx because the attacker's tip is higher.

7. Batcher executes the block: `deploy_account` succeeds (nonce 0→1); attacker's invoke runs `__validate__`, fails (empty signature), is rejected. Victim's invoke is no longer in the mempool and must be resubmitted. [6](#0-5) [7](#0-6) [2](#0-1)

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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
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
