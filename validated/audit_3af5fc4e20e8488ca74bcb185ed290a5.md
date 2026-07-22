After thorough investigation of the codebase, I found a valid analog. The structural parallel to the ERC721Pool bug is: a state condition designed for one scenario (account not yet deployed) is also satisfied by a different scenario (deployed account with nonce=0 and pending mempool tx), causing a subsequent operation (gateway validation) to proceed incorrectly — skipping signature validation for a transaction that should be validated.

---

### Title
Gateway `skip_stateful_validations` Admits Invoke Transactions with Invalid Signatures When Account Has Nonce=0 and Any Pending Mempool Transaction — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`skip_stateful_validations` is designed to skip the `__validate__` entry point for an invoke with nonce=1 when the account's on-chain nonce is 0 and a deploy_account is pending in the mempool (UX feature). However, the condition `account_tx_in_pool_or_recent_block` returns `true` for **any** account that has any transaction in the pool — not only accounts with a pending deploy_account. An attacker can exploit this to inject an invoke with an invalid signature into the mempool, consuming the victim account's nonce=1 slot and blocking the legitimate nonce=1 transaction.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` (lines 429–461) skips the blockifier `__validate__` call when three conditions are simultaneously true:

1. The incoming transaction is an `Invoke` with `tx.nonce() == Nonce(Felt::ONE)`
2. The account's on-chain nonce is `Nonce(Felt::ZERO)`
3. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true` [1](#0-0) 

Condition 3 is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

The code comment in `skip_stateful_validations` acknowledges the dual case: *"it means that either it has a deploy_account transaction **or transactions with future nonces that passed validations**."* The second case is the vulnerability: a deployed account with on-chain nonce=0 that has any pending transaction (e.g., a nonce=0 invoke, or a future-nonce invoke that passed validation) satisfies all three conditions, causing `__validate__` to be skipped for an attacker-supplied nonce=1 invoke with an invalid signature. [3](#0-2) 

The gateway flow calls `skip_stateful_validations` after `validate_by_mempool` and before `run_validate_entry_point`. When `skip_validate=true`, `run_validate_entry_point` sets `execution_flags.validate = false` and the blockifier `StatefulValidator::validate` is called without running `__validate__`: [4](#0-3) 

The transaction is then added to the mempool via `mempool_client.add_tx` without signature verification. [5](#0-4) 

When the batcher later executes the invalid transaction, `__validate__` is called and fails. The nonce is incremented in the non-revertible pre-validation phase (before `__validate__`), so the nonce=1 slot is permanently consumed: [6](#0-5) 

### Impact Explanation

An attacker who observes a target account (on-chain nonce=0, any pending tx in the mempool) can:

1. Submit an invoke with nonce=1 and an **invalid signature** for that account.
2. The gateway skips `__validate__` → the invalid transaction is admitted to the mempool.
3. After the nonce=0 transaction executes, the invalid nonce=1 transaction executes: `__validate__` fails, the transaction reverts, but the nonce is consumed (nonce becomes 2).
4. The legitimate owner's nonce=1 transaction is blocked (DuplicateNonce if submitted before execution, or NonceTooOld after).
5. The account is charged validation fees for the failed transaction.

This matches **High: Mempool/gateway/RPC admission accepts invalid transactions before sequencing** — an invalid (wrong-signature) transaction is accepted through account validation logic.

### Likelihood Explanation

The trigger condition is common: any newly deployed account (on-chain nonce=0) that has submitted its first transaction (nonce=0 pending in the mempool) is vulnerable. The deploy_account + invoke UX flow — explicitly supported and tested by the codebase — creates exactly this state for every new account. The attack requires only that the attacker submit a nonce=1 invoke before the legitimate user's nonce=1 invoke reaches the mempool, which is achievable by monitoring the public mempool. [7](#0-6) 

### Recommendation

Restrict the skip to the intended case: the account must not yet exist on-chain (i.e., the account contract has not been deployed). Add a state check that the account's class hash is zero (or the account address has no code), in addition to the existing nonce and mempool checks:

```rust
async fn skip_stateful_validations(...) -> ... {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
+           // Only skip if the account is truly not yet deployed (no class hash).
+           let class_hash = state_reader.get_class_hash_at(tx.sender_address())?;
+           if class_hash != ClassHash::default() {
+               return Ok(false); // Account exists; do not skip validation.
+           }
            ...
        }
    }
    Ok(false)
}
```

Alternatively, check that the pending mempool transaction for the account is specifically a `DeployAccount` transaction (not just any transaction).

### Proof of Concept

1. Deploy account `A` (on-chain nonce becomes 0 after deployment, or account has nonce=0 and has just submitted its first nonce=0 invoke).
2. Ensure account `A` has a pending nonce=0 transaction in the mempool (so `account_tx_in_pool_or_recent_block(A)` returns `true`).
3. Construct an `RpcInvokeTransactionV3` from address `A` with `nonce=1` and an **invalid signature** (e.g., all-zero signature).
4. Submit to the gateway's `add_tx` endpoint.
5. The gateway's `skip_stateful_validations` returns `true` (conditions: tx_nonce=1, account_nonce=0, account_in_pool=true).
6. `run_validate_entry_point` is called with `skip_validate=true` → `__validate__` is not called.
7. The invalid transaction is added to the mempool.
8. When the nonce=0 tx executes and nonce becomes 1, the invalid nonce=1 tx executes: `__validate__` fails, tx reverts, nonce becomes 2.
9. Account `A`'s legitimate nonce=1 transaction is permanently blocked. [8](#0-7)

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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L478-503)
```rust
    fn handle_nonce(
        state: &mut dyn State,
        tx_info: &TransactionInfo,
        strict: bool,
    ) -> TransactionPreValidationResult<()> {
        if tx_info.is_v0() {
            return Ok(());
        }

        let address = tx_info.sender_address();
        let account_nonce = state.get_nonce_at(address)?;
        let incoming_tx_nonce = tx_info.nonce();
        let valid_nonce = if strict {
            account_nonce == incoming_tx_nonce
        } else {
            account_nonce <= incoming_tx_nonce
        };
        if valid_nonce {
            return Ok(state.increment_nonce(address)?);
        }
        Err(TransactionPreValidationError::InvalidNonce {
            address,
            account_nonce,
            incoming_tx_nonce,
        })
    }
```

**File:** crates/apollo_integration_tests/src/utils.rs (L713-726)
```rust
/// Generates a deploy account transaction followed by an invoke transaction from the same account.
/// The first invoke_tx can be inserted to the first block right after the deploy_tx due to
/// the skip_validate feature. This feature allows the gateway to accept this transaction although
/// the account does not exist yet.
pub fn create_deploy_account_tx_and_invoke_tx(
    tx_generator: &mut MultiAccountTransactionGenerator,
    account_id: AccountId,
) -> Vec<RpcTransaction> {
    let undeployed_account_tx_generator = tx_generator.account_with_id_mut(account_id);
    assert!(!undeployed_account_tx_generator.is_deployed());
    let deploy_tx = undeployed_account_tx_generator.generate_deploy_account();
    let invoke_tx = undeployed_account_tx_generator.generate_trivial_rpc_invoke_tx(1);
    vec![deploy_tx, invoke_tx]
}
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator_test.rs (L151-190)
```rust
#[rstest]
#[case::should_skip_validation(
    executable_invoke_tx(invoke_tx_args!(nonce: nonce!(1))),
    nonce!(0),
    true,
    false
)]
#[case::should_not_skip_validation_nonce_zero(
    executable_invoke_tx(invoke_tx_args!(nonce: nonce!(0))),
    nonce!(0),
    true,
    true
)]
#[case::should_not_skip_validation_nonce_over_one(
    executable_invoke_tx(invoke_tx_args!(nonce: nonce!(2))),
    nonce!(0),
    true,
    true
)]
// TODO(Arni): Fix this test case. Ideally, we would have a non-invoke transaction with tx_nonce 1
// and account_nonce 0. For deploy account the tx_nonce is always 0. Replace with a declare tx.
#[case::should_not_skip_validation_non_invoke(
    executable_deploy_account_tx(deploy_account_tx_args!()),
    nonce!(0),
    true,
    true

)]
#[case::should_not_skip_validation_account_nonce_1(
    executable_invoke_tx(invoke_tx_args!(nonce: nonce!(1))),
    nonce!(1),
    true,
    true
)]
#[case::should_not_skip_validation_no_tx_in_mempool(
    executable_invoke_tx(invoke_tx_args!(nonce: nonce!(1))),
    nonce!(0),
    false,
    true
)]
```
