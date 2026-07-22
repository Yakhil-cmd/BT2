### Title
Gateway Admits Invoke Transactions With Unverified Signatures via Overly-Broad `skip_stateful_validations` Check - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`skip_stateful_validations` skips the `__validate__` entry-point call for any Invoke transaction with nonce=1 when the account has *any* transaction in the mempool or a recent block. The guard is supposed to cover only the deploy-account + invoke UX pattern (where the account does not yet exist on-chain), but it fires equally for existing accounts that merely have a prior nonce=0 invoke in the pool. An unprivileged attacker who controls an existing account (on-chain nonce=0) can therefore inject a nonce=1 invoke with an arbitrary, invalid signature into the mempool without the gateway ever calling `__validate__`.

### Finding Description

`skip_stateful_validations` is called inside `run_pre_validation_checks` after the nonce and resource-bounds checks pass:

```
run_pre_validation_checks
  └─ validate_state_preconditions   (nonce + resource bounds)
  └─ validate_by_mempool            (duplicate / nonce-gap check only)
  └─ skip_stateful_validations      ← decides whether __validate__ runs
```

The function's logic is:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 429-461
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            ...
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...;
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When this returns `true`, `run_validate_entry_point` sets `validate: false`, so `StatefulValidator::validate` is never called and the account's `__validate__` entry point is never executed:

```rust
// lines 311-312
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

The mempool-side check `account_tx_in_pool_or_recent_block` does not distinguish transaction types:

```rust
// crates/apollo_mempool/src/mempool.rs  lines 697-700
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

The code comment claims this is safe because the account "either has a deploy_account transaction or transactions with future nonces that passed validations." The second branch is the flaw: a nonce=0 *invoke* (not a deploy_account) that passed `__validate__` is sufficient to make `account_tx_in_pool_or_recent_block` return `true`, which then causes the nonce=1 invoke to bypass signature verification entirely.

### Impact Explanation

An attacker who controls an existing account X with on-chain nonce=0 can:

1. Submit a valid Invoke (nonce=0) for X. The gateway calls `__validate__`, it passes, the transaction enters the mempool. `account_tx_in_pool_or_recent_block(X)` now returns `true`.
2. Submit a second Invoke (nonce=1) for X with a completely arbitrary/invalid signature. `skip_stateful_validations` fires, `validate: false` is set, `__validate__` is never called. The transaction passes all remaining checks (nonce in range, resource bounds, mempool duplicate check) and is admitted to the mempool.

The mempool now holds a transaction whose signature has never been verified. This matches the **High** impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."*

During actual block execution `AccountTransaction::new_for_sequencing` always sets `validate: true`, so the invalid transaction will eventually fail `__validate__` and be reverted, but it has already consumed a mempool slot and will consume sequencer execution resources. [4](#0-3) 

### Likelihood Explanation

The trigger requires only an existing account with on-chain nonce=0 (any freshly-deployed account qualifies) and the ability to submit two RPC transactions. No privileged access is needed. The condition `tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO)` is a normal state for any account that was just deployed and has not yet executed its first post-deploy transaction.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **deploy_account** transaction for the sender address is present in the mempool. Expose a dedicated `deploy_account_in_pool(address)` query on the mempool interface and use that instead. This preserves the intended UX improvement while closing the bypass for existing accounts.

### Proof of Concept

```
1. Deploy account X on-chain (nonce becomes 0).

2. POST /gateway/add_transaction
   { type: INVOKE, sender_address: X, nonce: 0, signature: [valid_sig], ... }
   → Gateway calls __validate__ → passes → mempool admits tx
   → account_tx_in_pool_or_recent_block(X) == true

3. POST /gateway/add_transaction
   { type: INVOKE, sender_address: X, nonce: 1, signature: [0xdeadbeef, 0xdeadbeef], ... }
   → skip_stateful_validations: nonce==1 && account_nonce==0 && pool_check==true → returns true
   → run_validate_entry_point sets validate=false → __validate__ NOT called
   → mempool admits tx with invalid signature

4. Batcher calls get_txs(), receives the nonce=1 tx.
   AccountTransaction::new_for_sequencing sets validate=true.
   __validate__ is called during execution → fails → tx reverted.
   Sequencer wasted execution resources; mempool slot was consumed.
``` [5](#0-4) [6](#0-5)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L399-461)
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
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
