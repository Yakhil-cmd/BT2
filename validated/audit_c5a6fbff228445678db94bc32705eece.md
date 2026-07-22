Looking at the `skip_stateful_validations` function and the `account_tx_in_pool_or_recent_block` check, I can identify a direct analog to the `addLiquidity` authorization bypass.

### Title
Signature Verification Bypass via Overly Broad `account_tx_in_pool_or_recent_block` Guard in `skip_stateful_validations` — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function skips the `__validate__` entry-point call (i.e., signature verification) for any invoke transaction with `nonce=1` whose sender address appears in the mempool, regardless of *why* it appears there. An attacker who observes a legitimate user's pending `deploy_account` for address `A` can immediately submit an invoke transaction with `sender_address=A`, `nonce=1`, and a completely invalid signature. The gateway admits it to the mempool without ever calling `__validate__`, matching the "anyone can act on behalf of another address" pattern from the seed report.

---

### Finding Description

`skip_stateful_validations` is the UX feature that lets a user send `deploy_account` (nonce 0) and the first `invoke` (nonce 1) simultaneously, before the account exists on-chain. The skip condition is:

```
tx is Invoke
  AND tx.nonce == 1
  AND account_on_chain_nonce == 0
  AND account_tx_in_pool_or_recent_block(sender_address) == true
``` [1](#0-0) 

The guard `account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

This returns `true` for **any** account that has ever appeared in the mempool or a recent committed block — not specifically for accounts that have a *pending deploy_account*. The code comment acknowledges this conflation:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

That reasoning is circular: future-nonce invokes for a nonce-0 account can only have passed validation via this same skip mechanism.

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `validate: false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [3](#0-2) 

This means `AccountTransaction::validate_tx` returns `Ok(None)` immediately without executing the account's `__validate__` entry point:

```rust
fn validate_tx(...) -> ... {
    if !self.execution_flags.validate {
        return Ok(None);
    }
    ...
}
``` [4](#0-3) 

The full gateway admission path for the attacker's transaction:

1. **`validate_nonce`** — passes: `0 ≤ 1 ≤ 0 + max_allowed_nonce_gap`. [5](#0-4) 
2. **`validate_by_mempool`** — passes: mempool checks nonce/fee, not signature. [6](#0-5) 
3. **`skip_stateful_validations`** — returns `true` because the victim's `deploy_account` already placed address `A` in the mempool. [7](#0-6) 
4. **`run_validate_entry_point`** — skips `__validate__`; transaction is admitted. [8](#0-7) 

---

### Impact Explanation

An attacker can submit an invoke transaction with an **arbitrary invalid signature** for any account that has a pending `deploy_account` in the mempool. The transaction is admitted to the mempool without signature verification. This matches the allowed impact: **"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

Secondary consequences:
- The attacker's invalid invoke competes with the legitimate user's nonce-1 invoke. Via the mempool's fee-escalation replacement logic, a higher-fee attacker invoke can **displace** the legitimate user's invoke, breaking the deploy-account + invoke UX flow.
- The mempool can be flooded with signature-invalid transactions for any address that has a pending `deploy_account`, consuming mempool capacity and batcher resources.

---

### Likelihood Explanation

The mempool is observable (transactions are gossiped over P2P and visible via RPC). Any attacker can watch for `deploy_account` transactions and immediately submit a competing nonce-1 invoke for the same address. No privileged access is required; the only precondition is that a legitimate user is deploying a new account.

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** is pending for the sender address. For example, expose a `has_pending_deploy_account(address)` query from the mempool, or require the invoke transaction to carry the hash of the associated `deploy_account` transaction (as the legacy `PyValidator` does via `deploy_account_tx_hash: Option<TransactionHash>`). [9](#0-8) 

---

### Proof of Concept

```
1. Legitimate user submits:
     deploy_account { sender=A, nonce=0, valid_sig }
   → A is now in mempool; account_tx_in_pool_or_recent_block(A) == true

2. Attacker submits:
     invoke { sender_address=A, nonce=1, calldata=<drain funds>, signature=0x0 }

3. Gateway stateful validation:
     validate_nonce(1, account_nonce=0)          → OK (within gap)
     validate_by_mempool(...)                    → OK (no sig check)
     skip_stateful_validations(nonce=1, acct=0)  → true (A in mempool)
     run_validate_entry_point(skip=true)         → __validate__ NOT called

4. Attacker's invoke is admitted to the mempool with an invalid signature.

5. Attacker resubmits with fee > legitimate user's nonce-1 invoke fee.
   → Mempool fee-escalation replaces the legitimate invoke with the attacker's.

6. Batcher processes the block:
     deploy_account(A) executes → A deployed, nonce=0→1
     attacker's invoke(A, nonce=1) → __validate__ called → FAILS (invalid sig)
     → transaction rejected; legitimate user's invoke is gone from mempool.
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L413-424)
```rust
/// Perform transaction validation by the mempool.
async fn validate_by_mempool(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<()> {
    let validation_args = ValidationArgs::new(tx, account_nonce);
    mempool_client
        .validate_tx(validation_args)
        .await
        .map_err(|err| mempool_client_err_to_deprecated_gw_err(&tx.signature(), err))
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
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
