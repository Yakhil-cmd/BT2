### Title
Gateway `skip_stateful_validations` Accepts Any Mempool Transaction as Proof of Pending Deployment, Bypassing `__validate__` for Invoke Transactions — (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator is designed to skip `__validate__` for an invoke transaction with nonce=1 when a deploy_account transaction is pending in the mempool (UX optimization for the deploy_account + invoke pattern). However, the guard condition checks whether **any** transaction from the sender address exists in the mempool, not specifically a deploy_account transaction. An attacker who controls a contract deployed via the `deploy` syscall (nonce=0 in state, but code present) can first submit a future-nonce invoke that passes `__validate__` normally, then submit a nonce=1 invoke with an invalid or arbitrary signature — the gateway skips `__validate__` entirely for the second transaction and admits it to the mempool.

---

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` lines 429–461:

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            // ...
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())  // ← checks ANY tx
                .await
                ...
        }
    }
    Ok(false)
}
``` [1](#0-0) 

The comment justifies the check: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."*

The second branch of that reasoning is flawed. When `account_nonce == Nonce(Felt::ZERO)`, a contract deployed via the `deploy` syscall (not via deploy_account) has code at its address but nonce=0. A future-nonce invoke (e.g., nonce=2) from that address passes the gateway's nonce range check:

```rust
// Other transactions must be within the allowed nonce range.
_ => {
    let max_allowed_nonce =
        Nonce(account_nonce.0 + Felt::from(self.config.max_allowed_nonce_gap));
    if !(account_nonce <= incoming_tx_nonce && incoming_tx_nonce <= max_allowed_nonce) {
        return Err(create_error(...));
    }
}
``` [2](#0-1) 

and passes `__validate__` (the contract has code). Once that nonce=2 tx is in the pool, `account_tx_in_pool_or_recent_block` returns `true`:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

This causes `skip_stateful_validations` to return `true` for the subsequent nonce=1 invoke, even though no deploy_account transaction exists.

`run_validate_entry_point` then sets `validate: false` in the execution flags:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [4](#0-3) 

and `StatefulValidator::perform_validations` returns `Ok(())` without calling `__validate__`:

```rust
ApiTransaction::Invoke(_) => {
    let tx_context = ...;
    tx.perform_pre_validation_stage(self.state(), &tx_context)?;
    if !tx.execution_flags.validate {
        return Ok(());   // ← exits here; __validate__ never runs
    }
    ...
}
``` [5](#0-4) 

The nonce=1 invoke is admitted to the mempool without any signature verification at the gateway.

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

The gateway's admission-control invariant is: only transactions that pass `__validate__` (signature verification) are admitted to the mempool. This invariant is broken for invoke transactions with nonce=1 from accounts with nonce=0 that have any other transaction in the mempool.

Concretely:
- An attacker can submit invoke transactions with arbitrary or invalid signatures from a contract they deployed via the `deploy` syscall, bypassing the gateway's signature check.
- These transactions are admitted to the mempool and forwarded to the batcher.
- During execution the batcher uses `new_for_sequencing` which sets `validate: true`, so `__validate__` runs again and the transaction is reverted with fees charged. However, the gateway's pre-sequencing admission gate has been bypassed.
- This enables mempool flooding with transactions that will be reverted, consuming mempool capacity and batcher execution resources without the attacker having passed signature verification at admission time.

---

### Likelihood Explanation

**Medium.** The precondition — a contract at nonce=0 deployed via the `deploy` syscall — is a normal Starknet pattern (e.g., factory-deployed accounts, counterfactual deployments). The attacker only needs to submit one valid future-nonce invoke to prime the mempool state, then submit the nonce=1 invoke with an invalid signature. No privileged access is required.

---

### Recommendation

Replace the `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **deploy_account** transaction exists in the mempool for the sender address. The mempool should expose a dedicated query such as `deploy_account_tx_in_pool(address) -> bool` that inspects the transaction type, not merely the address presence. The corrected guard should be:

```rust
// Only skip __validate__ if a deploy_account tx is pending for this account.
return mempool_client
    .deploy_account_tx_in_pool(tx.sender_address())
    .await
    ...
```

This mirrors the fix in the referenced external report: enforcing that the account field is of the specific required type (deploy_account), not merely any account-associated object.

---

### Proof of Concept

1. Deploy contract `X` via `deploy` syscall from another contract. `X` has code; its on-chain nonce is `0` (no deploy_account transaction was ever sent from `X`).
2. Submit invoke `T2` with `nonce=2`, `sender=X`, valid signature. Gateway nonce check passes (`0 ≤ 2 ≤ max_allowed_nonce_gap`). `__validate__` runs and passes (X has code). `T2` enters the mempool. `account_tx_in_pool_or_recent_block(X)` now returns `true`.
3. Submit invoke `T1` with `nonce=1`, `sender=X`, **invalid/arbitrary signature**.
   - `validate_state_preconditions`: nonce=1 is within range → passes.
   - `validate_by_mempool`: nonce=1 ≥ account_nonce=0, no duplicate → passes.
   - `skip_stateful_validations`: `nonce==1 && account_nonce==0` → checks `account_tx_in_pool_or_recent_block(X)` → `true` (T2 is in pool) → returns `true` (skip).
   - `run_validate_entry_point` called with `skip_validate=true` → `validate: false` → `__validate__` is **not called**.
4. `T1` is admitted to the mempool without signature verification.
5. Batcher picks up `T1`, executes with `validate: true` (from `new_for_sequencing`). `__validate__` runs, fails on invalid signature, `T1` is reverted and fee is charged. The gateway admission invariant was nonetheless violated at step 4. [6](#0-5) [7](#0-6)

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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-94)
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
