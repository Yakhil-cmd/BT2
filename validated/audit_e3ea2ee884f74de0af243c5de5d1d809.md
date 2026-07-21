### Title
Gateway Admits Unsigned Invoke Transactions via `skip_stateful_validations` Bypass — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry-point call (i.e., signature verification) for any invoke transaction with `nonce == 1` sent to an address whose on-chain nonce is still `0`, provided `account_tx_in_pool_or_recent_block` returns `true` for that address. Because the mempool's `account_tx_in_pool_or_recent_block` check is satisfied by the mere presence of *any* transaction for the target address in the pool — not specifically a deploy-account transaction submitted by the legitimate owner — an unprivileged attacker who observes a pending `deploy_account` for address X can submit a forged invoke with `nonce=1` for X, bypassing signature verification at the gateway and having the transaction admitted to the mempool.

### Finding Description

**Trigger condition.** `skip_stateful_validations` returns `true` (skip) when all three hold:

1. The incoming transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed on-chain).
4. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [1](#0-0) 

**What the check actually verifies.** `account_tx_in_pool_or_recent_block` returns `true` if the address appears in `MempoolState.staged`, `MempoolState.committed`, or `TransactionPool`: [2](#0-1) [3](#0-2) 

The comment in the code acknowledges this is a proxy check: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* The check does **not** verify that the incoming invoke is signed by the same key that controls address X.

**Effect of skipping.** When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false` and the blockifier's `StatefulValidator::perform_validations` returns `Ok(())` immediately after `perform_pre_validation_stage`, without ever calling `__validate__`: [4](#0-3) [5](#0-4) 

**`perform_pre_validation_stage` does not block the attack.** The nonce check (`strict_nonce_check = false`) accepts any nonce `>= account_nonce`, so nonce 1 passes when account nonce is 0. The fee/balance check (`verify_can_pay_committed_bounds`) passes because Starknet accounts must be pre-funded before deployment — the target address already holds STRK/ETH at the time the deploy_account is pending. [6](#0-5) [7](#0-6) 

**`validate_by_mempool` does not block the attack.** The mempool's `validate_tx` path only checks for duplicate hashes and nonce ordering (`tx_nonce >= account_nonce`); it does not verify signatures: [8](#0-7) 

**Attack scenario.**

1. Attacker observes a pending `deploy_account` for address X in the public mempool.
2. Address X is pre-funded (required for the deploy_account to succeed).
3. Attacker crafts an `Invoke` V3 transaction: `sender_address = X`, `nonce = 1`, arbitrary calldata, valid resource bounds, **arbitrary/forged signature**.
4. Gateway stateless validator passes (non-zero resource bounds, valid DA modes, etc.).
5. Gateway stateful validator: `account_nonce = 0`, `tx.nonce() = 1`, `account_tx_in_pool_or_recent_block(X) = true` → `skip_validate = true` → `__validate__` is never called → transaction admitted.
6. Forged transaction enters the mempool alongside the legitimate deploy_account + invoke pair.

### Impact Explanation

The gateway/mempool admission layer accepts an invalid transaction — one that carries a forged or absent signature — before sequencing. This violates the invariant that every transaction in the mempool has passed account-level signature verification. Consequences include:

- **Mempool pollution**: Attackers can flood the mempool with unsigned invoke transactions targeting any address with a pending deploy_account, degrading throughput for legitimate users.
- **Block space waste**: The batcher will select these transactions; they will revert during execution (when `__validate__` is called with `validate: true` by the batcher), consuming proving/execution resources.
- **Disruption of the deploy_account + invoke UX flow**: The legitimate user's nonce-1 invoke may be displaced or delayed by the attacker's forged nonce-1 transaction (duplicate nonce in the pool for the same address).

This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

- The mempool is publicly observable; any pending `deploy_account` is visible.
- Starknet accounts must be pre-funded before deployment, so the balance check always passes.
- The attack requires only a single crafted transaction with a known sender address and nonce=1.
- No privileged access is required.

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` proxy with a check that specifically verifies a `deploy_account` transaction for the same sender address is present in the mempool. Alternatively, do not skip `__validate__` entirely; instead, run it against a synthetic "pre-deployment" state that treats the account as deployed (using the class hash from the pending deploy_account). This preserves the UX benefit while ensuring every admitted transaction carries a valid signature.

### Proof of Concept

```
1. Submit deploy_account for address X (legitimate user action).
   → deploy_account enters mempool pool; account_tx_in_pool_or_recent_block(X) = true.

2. Attacker submits:
   InvokeV3 {
     sender_address: X,
     nonce: 1,
     calldata: [<arbitrary>],
     resource_bounds: { l2_gas: { max_amount: 1000000, max_price_per_unit: 1 }, ... },
     signature: [0xdeadbeef],   // forged
   }

3. Gateway stateless check: passes (non-zero bounds, valid DA modes).

4. Gateway stateful check:
   account_nonce = get_nonce_from_state(X) = 0   // not deployed yet
   validate_nonce: 0 <= 1 <= max_allowed_nonce_gap  ✓
   validate_resource_bounds: passes (pre-funded balance covers bounds)  ✓
   validate_by_mempool: nonce 1 >= 0  ✓
   skip_stateful_validations:
     tx.nonce() == 1 && account_nonce == 0  → true
     account_tx_in_pool_or_recent_block(X)  → true (deploy_account is in pool)
     → skip_validate = true
   run_validate_entry_point: execution_flags.validate = false
     → StatefulValidator returns Ok() without calling __validate__

5. Forged invoke admitted to mempool.
   Batcher selects it → execution calls __validate__ → reverts.
   Block space consumed; legitimate user's nonce-1 invoke may be evicted.
``` [9](#0-8) [10](#0-9)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L426-461)
```rust
/// Check if validation of an invoke transaction should be skipped due to deploy_account not being
/// processed yet. This feature is used to improve UX for users sending deploy_account + invoke at
/// once.
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

**File:** crates/apollo_mempool/src/mempool.rs (L115-117)
```rust
    fn contains_account(&self, address: ContractAddress) -> bool {
        self.staged.contains_key(&address) || self.committed.contains_key(&address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L162-174)
```rust
    fn validate_incoming_tx(
        &self,
        tx_reference: TransactionReference,
        incoming_account_nonce: Nonce,
    ) -> MempoolResult<()> {
        let TransactionReference { address, nonce: tx_nonce, .. } = tx_reference;
        let account_nonce = self.resolve_nonce(address, incoming_account_nonce);
        if tx_nonce < account_nonce {
            return Err(MempoolError::NonceTooOld { address, tx_nonce, account_nonce });
        }

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
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
