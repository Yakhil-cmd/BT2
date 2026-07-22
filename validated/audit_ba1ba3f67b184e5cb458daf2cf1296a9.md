### Title
`skip_stateful_validations` Bypasses `__validate__` Signature Check for Invoke Transactions with Nonce=1 When Any Account Transaction Exists in Pool - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry-point call (which performs signature verification) for any Invoke transaction with nonce=1 when `account_tx_in_pool_or_recent_block` returns `true`. The check is too broad: it returns `true` for **any** transaction in the pool for that address, not specifically a `deploy_account`. An attacker who controls an address (by choosing class hash, salt, and constructor calldata) can submit a valid `deploy_account` to satisfy the pool check, then submit an Invoke with nonce=1 carrying an **arbitrary/invalid signature** that is admitted to the mempool without any signature verification.

### Finding Description

In `run_validate_entry_point`, the `skip_validate` boolean directly controls `ExecutionFlags::validate`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [1](#0-0) 

When `validate` is `false`, `AccountTransaction::validate_tx` returns `Ok(None)` immediately without calling the `__validate__` entry point:

```rust
fn validate_tx(...) {
    if !self.execution_flags.validate {
        return Ok(None);
    }
    ...
}
``` [2](#0-1) 

`skip_validate` is set to `true` by `skip_stateful_validations` when all three conditions hold:

1. The transaction is an `Invoke` with `nonce == 1`
2. The on-chain account nonce is `0` (account not yet deployed)
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true` [3](#0-2) 

The code comment claims this is safe because the account "either has a deploy_account transaction or transactions with future nonces that passed validations." However, `account_tx_in_pool_or_recent_block` only checks:

```rust
self.state.contains_account(account_address) || self.tx_pool.contains_account(account_address)
``` [4](#0-3) 

It does **not** verify that the matching pool transaction is specifically a `deploy_account`. Any transaction type for that address satisfies the check.

**Attack path:**

1. Attacker derives address X deterministically (choosing class hash, salt, constructor calldata).
2. Attacker submits a valid `deploy_account` for X → passes all validations, enters the mempool.
3. Attacker submits an `Invoke` for X with `nonce=1` and an **invalid/arbitrary signature**.
4. Gateway checks: `account_nonce == 0` ✓, `tx.nonce() == 1` ✓, `account_tx_in_pool_or_recent_block(X) == true` ✓ (deploy_account is in pool).
5. `skip_validate = true` → `run_validate_entry_point` sets `execution_flags.validate = false`.
6. `StatefulValidator::perform_validations` returns `Ok(())` without calling `__validate__`. [5](#0-4) 

7. The Invoke with invalid signature is admitted to the mempool.

### Impact Explanation

The gateway/mempool admission path accepts an Invoke transaction whose signature has never been verified. This directly matches the "High" impact scope: **"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."** The invalid transaction will eventually fail at execution time when the batcher calls `__validate__` on the deployed account, but it has already been admitted past the gateway's security boundary without any cryptographic authorization check.

### Likelihood Explanation

The attack requires only two sequential RPC calls: one valid `deploy_account` (which the attacker fully controls by choosing its parameters) and one Invoke with nonce=1. No privileged access, special network position, or race condition is required. The attacker fully controls the address derivation, making the `deploy_account` trivially constructable. The condition `nonce == 1 && account_nonce == 0` is the exact scenario the UX feature targets, so it is reliably triggerable.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction exists in the pool for the sender address. Add a dedicated mempool query such as `deploy_account_tx_in_pool(address) -> bool` that inspects the transaction type, rather than relying on the presence of any transaction for that address.

### Proof of Concept

```
1. Attacker picks: class_hash=C, salt=S, constructor_calldata=D
   → contract_address X = hash(C, S, D, deployer=0)

2. POST /add_transaction  (deploy_account, address=X, nonce=0, valid_sig)
   → Gateway: stateless OK, stateful OK (nonce=0, account_nonce=0)
   → Mempool: deploy_account for X admitted

3. POST /add_transaction  (invoke, sender=X, nonce=1, calldata=ATTACK, sig=0xDEAD_INVALID)
   → Gateway stateless: OK (signature length check passes, no crypto check)
   → validate_nonce: account_nonce=0, tx_nonce=1, max_allowed_nonce_gap≥1 → OK
   → validate_by_mempool: nonce not too old, no duplicate hash → OK
   → skip_stateful_validations:
       tx.nonce()==1 ✓, account_nonce==0 ✓,
       account_tx_in_pool_or_recent_block(X)==true ✓  (deploy_account is in pool)
       → returns true
   → run_validate_entry_point(skip_validate=true):
       execution_flags.validate = false
       StatefulValidator::perform_validations → returns Ok(()) without __validate__
   → Invoke with invalid signature admitted to mempool ✓

4. Batcher later executes deploy_account → account X deployed
5. Batcher executes invoke → __validate__ called → fails (invalid sig) → reverted
   (State is safe, but admission invariant was broken at step 3)
``` [6](#0-5) [7](#0-6)

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
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
