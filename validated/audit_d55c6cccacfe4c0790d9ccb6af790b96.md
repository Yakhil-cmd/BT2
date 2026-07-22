### Title
Gateway Admits Unsigned Invoke Transactions via `skip_stateful_validations` Bypass — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` path unconditionally skips the blockifier's `__validate__` entry-point call for any Invoke transaction with `nonce == 1` when the on-chain account nonce is `0` and `account_tx_in_pool_or_recent_block` returns `true`. Because the account contract does not yet exist, the cryptographic signature is never verified. An unprivileged attacker who observes the public mempool can submit Invoke transactions with arbitrary (fake) signatures for any account that has a pending `deploy_account`, and those transactions will be admitted to the mempool without any signature check.

---

### Finding Description

**Two-phase split with no re-check at execution time (analog to the external bug)**

The external bug's root cause is a two-phase pattern: a request is validated (completion-status check), pushed to a queue, and then executed without re-running the completion check. The Sequencer has an analogous two-phase split:

1. **Phase 1 – Gateway stateful validation** (`extract_state_nonce_and_run_validations`):
   - `run_pre_validation_checks` → `validate_by_mempool` (nonce/duplicate check only) → `skip_stateful_validations` (returns `true` when conditions below hold)
   - `run_validate_entry_point` is called with `validate: !skip_validate`, so when `skip_validate == true` the `ExecutionFlags.validate` field is `false`.

2. **Phase 2 – Blockifier `perform_validations`** (inside `run_validate_entry_point`):
   ```rust
   // stateful_transaction_validator.rs:311-312
   let execution_flags =
       ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
   ```
   Inside `StatefulValidator::perform_validations`:
   ```rust
   // blockifier/src/blockifier/stateful_validator.rs:79-81
   if !tx.execution_flags.validate {
       return Ok(());
   }
   ```
   The `__validate__` entry point — the only place where the account's cryptographic signature is verified — is **never called**.

**Trigger condition** (`skip_stateful_validations`):

```rust
// stateful_transaction_validator.rs:437-456
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await ...
}
```

All three conditions are attacker-controllable or publicly observable:
- `tx.nonce() == 1` — attacker sets this field.
- `account_nonce == 0` — the target account has not been deployed yet (public state).
- `account_tx_in_pool_or_recent_block` — the mempool is public; any account with a pending `deploy_account` satisfies this.

**What is NOT checked:**
- The stateless validator checks signature *length* but not cryptographic validity.
- `validate_by_mempool` checks for duplicate hashes and nonce ordering — not signatures.
- No other path verifies the signature before the transaction is forwarded to `mempool_client.add_tx`.

---

### Impact Explanation

An attacker can:
1. Watch the public mempool for any account address `A` that has a pending `deploy_account` (account nonce = 0 on-chain).
2. Craft an Invoke transaction for `A` with `nonce = 1` and a completely arbitrary signature.
3. Submit it to the gateway. The gateway skips `__validate__`, and `mempool_client.add_tx` succeeds.
4. The invalid Invoke is now in the mempool, consuming capacity and batcher execution budget.

The transactions will revert during block execution (the blockifier always runs `__validate__` during actual execution), but:
- They occupy mempool slots, potentially evicting legitimate transactions.
- The batcher wastes execution resources on them.
- For every account with a pending `deploy_account`, the attacker can inject one such invalid Invoke (one per `(address, nonce)` slot).

This matches the allowed impact: **"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

---

### Likelihood Explanation

- The mempool is publicly observable (P2P gossip, RPC `starknet_getPendingTransactions`).
- Crafting an Invoke with `nonce = 1` and a fake signature requires no privileged access.
- The only prerequisite is the existence of a `deploy_account` in the mempool for the target address, which is a normal user action.
- No special timing or concurrency is required.

---

### Recommendation

The `skip_stateful_validations` path should not be a complete bypass of signature verification. Options:

1. **Verify against the expected class**: The `deploy_account` transaction in the mempool carries the `class_hash` and `constructor_calldata`. The gateway can instantiate a temporary state with the would-be deployed contract and run `__validate__` against it.
2. **Restrict the skip to the submitter's own session**: Require that the Invoke and the `deploy_account` arrive in the same gateway request (e.g., a batch endpoint), so the gateway can correlate them.
3. **Rate-limit or stake-gate** the skip path so that spamming it has a cost.

At minimum, add a note in the admission logic that this path admits transactions without signature verification, and ensure the mempool's capacity accounting treats such transactions as lower-priority or evictable.

---

### Proof of Concept

```
# 1. Alice submits a deploy_account for address 0xALICE (nonce=0).
#    The mempool now contains: deploy_account(0xALICE, nonce=0).

# 2. Attacker observes the mempool and sees 0xALICE has a pending deploy_account.

# 3. Attacker crafts an Invoke:
#      sender_address = 0xALICE
#      nonce          = 1
#      signature      = [0xDEAD, 0xBEEF]   # completely fake
#      calldata       = [<any target>, <any selector>]

# 4. Attacker submits the Invoke to the gateway.
#    Gateway flow:
#      stateless_tx_validator.validate()          -> OK (signature length is valid)
#      get_nonce_from_state(0xALICE)              -> Nonce(0)   (account not deployed)
#      validate_nonce()                           -> OK (0 <= 1 <= 0+max_gap)
#      validate_by_mempool()                      -> OK (no duplicate hash/nonce)
#      skip_stateful_validations():
#        nonce==1 && account_nonce==0             -> true
#        account_tx_in_pool_or_recent_block()     -> true (deploy_account is there)
#        returns true
#      run_validate_entry_point(skip_validate=true):
#        ExecutionFlags { validate: false, ... }
#        StatefulValidator::perform_validations() -> returns Ok(()) immediately
#      mempool_client.add_tx()                    -> OK

# 5. The Invoke with fake signature is now in the mempool.
#    It will fail during block execution when __validate__ is called,
#    but it has already consumed a mempool slot and will waste batcher resources.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```
