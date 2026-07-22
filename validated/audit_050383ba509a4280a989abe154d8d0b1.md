After thorough investigation of the codebase, I found a genuine analog to the external bug. The structural parallel is: the external bug uses a sequence number as a key that is only unique within a provider namespace, while the sequencer uses an "account in pool" check that is supposed to be specific to `deploy_account` transactions but actually matches any transaction type.

---

### Title
Gateway `skip_stateful_validations` Bypasses `__validate__` for Invoke Transactions When Any Prior Transaction Exists in Mempool, Not Just `deploy_account` — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway is designed to skip the `__validate__` entry-point call for an invoke transaction with nonce=1 when the account has not yet been deployed (account nonce=0) and a `deploy_account` is pending in the mempool. The check it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** transaction from that address in the pool, not specifically a `deploy_account`. An attacker with an already-deployed account at nonce=0 can submit a regular invoke(nonce=0) to seed the pool, then submit an invoke(nonce=1) with an invalid signature or a failing `__validate__` body. The gateway skips `__validate__` for the second transaction and admits it to the mempool, violating the invariant that every admitted transaction has passed account validation.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` fires when:

```
tx.nonce() == Nonce(Felt::ONE)  &&  account_nonce == Nonce(Felt::ZERO)
```

and `account_tx_in_pool_or_recent_block(sender)` returns `true`. [1](#0-0) 

The intent is to support the UX pattern "send `deploy_account` + `invoke` in the same batch": the account has no code yet, so `__validate__` cannot run, and the gateway trusts that the pending `deploy_account` will install the code before the invoke is executed.

The implementation of `account_tx_in_pool_or_recent_block` is:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

It checks only whether **any** transaction from the address is present — it does not distinguish `deploy_account` from `invoke`. The comment in `skip_stateful_validations` acknowledges this ambiguity but incorrectly concludes it is safe:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

The reasoning is circular: an already-deployed account with nonce=0 can have an invoke(nonce=0) in the pool that passed `__validate__`. That invoke's presence satisfies the check, causing the gateway to skip `__validate__` for the subsequent invoke(nonce=1) — even though the account is fully deployed and `__validate__` should be enforced.

**Attack steps:**

1. Attacker controls a deployed account at address `A` with on-chain nonce=0.
2. Attacker submits `invoke(nonce=0, valid_sig)` → passes all gateway checks including `__validate__`; enters the mempool.
3. Attacker submits `invoke(nonce=1, invalid_sig_or_failing_validate)`.
   - `validate_nonce`: nonce=1 is within `[0, 0+200]` → passes.
   - `skip_stateful_validations`: nonce==1, account_nonce==0, `account_tx_in_pool_or_recent_block(A)` == true (because invoke(nonce=0) is in pool) → returns `true`.
   - `run_validate_entry_point` is called with `skip_validate=true`, setting `execution_flags.validate = false`.
   - `__validate__` is **not called** at the gateway.
4. `invoke(nonce=1)` is admitted to the mempool without signature/account validation. [3](#0-2) 

When the batcher later executes the transaction, `execution_flags.validate` is reset to `true` (the stored `InternalRpcTransaction` carries no `execution_flags`), so `__validate__` runs and the transaction reverts — but it has already been sequenced and the nonce is consumed.

### Impact Explanation

The gateway's core admission invariant — *every accepted transaction has passed account `__validate__`* — is broken for invoke transactions with nonce=1 from any already-deployed account that has a concurrent nonce=0 transaction in the pool. This matches the allowed impact: **"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."**

Concrete consequences:
- Transactions with invalid signatures are admitted to the mempool and included in blocks.
- The account's nonce is incremented for a reverted transaction, potentially disrupting legitimate pending transactions.
- The mempool can be seeded with transactions that are guaranteed to revert, wasting block space.

### Likelihood Explanation

Any unprivileged user with a deployed account at nonce=0 can trigger this. No admin action or race condition is required. The attacker simply submits two transactions in sequence. The condition `nonce==1 && account_nonce==0` is common during normal account lifecycle (first two transactions ever sent from a new account).

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a type-specific query that returns `true` only when a `deploy_account` transaction for the address is pending in the pool or was recently committed. For example, add a `deploy_account_in_pool_or_recent_block(address)` method to the mempool that inspects transaction type, and use it exclusively in `skip_stateful_validations`.

Alternatively, store the transaction type alongside the account address in the mempool's `state` map so the existing API can be made type-aware without a new RPC.

### Proof of Concept

```
// Precondition: account at address A is deployed, on-chain nonce = 0.

// Step 1 – seed the pool with a valid invoke at nonce 0.
gateway.add_tx(invoke_v3 {
    sender_address: A,
    nonce: 0,
    signature: valid_sig,   // passes __validate__
    calldata: [...],
}).await;

// Step 2 – submit invoke at nonce 1 with an invalid signature.
// skip_stateful_validations fires because:
//   tx.nonce() == 1, account_nonce == 0,
//   account_tx_in_pool_or_recent_block(A) == true  ← triggered by step 1
gateway.add_tx(invoke_v3 {
    sender_address: A,
    nonce: 1,
    signature: [0x0, 0x0],  // invalid – would fail __validate__
    calldata: [...],
}).await;
// Returns Ok(tx_hash) — transaction admitted without __validate__.

// Step 3 – batcher executes the block:
//   invoke(nonce=0) executes normally.
//   invoke(nonce=1) runs __validate__ → FAILS → reverts.
//   Nonce of A is now 2; the attacker's nonce=1 slot is consumed.
```

The root cause is in `skip_stateful_validations` at: [4](#0-3) 

which calls: [2](#0-1) 

without verifying that the matching pool entry is a `deploy_account` transaction.

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-458)
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
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```
