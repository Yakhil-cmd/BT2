After exhaustively tracing the external bug's invariant through the Sequencer codebase, I found no reachable analog.

**Invariant being tested:** A state slot is read, an external/async call is made that can write to the same slot, and then the original function unconditionally overwrites that slot — deleting the intermediate write.

**What I searched:**

1. **`concurrency_execute_fee_transfer`** (`crates/blockifier/src/transaction/account_transaction.rs:599-623`) — creates a nested `TransactionalState`, executes the fee transfer, then explicitly `remove`s the sequencer-balance writes before `commit()`. This is the closest structural match: a write is deleted after an "external" call. However, the deletion is intentional and the correct balance is reapplied later by `complete_fee_transfer_flow` / `add_fee_to_sequencer_balance`. No slot is lost. [1](#0-0) 

2. **`skip_stateful_validations` / `account_tx_in_pool_or_recent_block`** (`crates/apollo_gateway/src/stateful_transaction_validator.rs:429-460`) — reads account nonce, makes an async call to the mempool, and conditionally skips `__validate__`. The nonce read and the skip decision are both read-only; no state slot is written after the async call. [2](#0-1) 

3. **`convert_rpc_tx_to_internal` / `add_class`** (`crates/apollo_transaction_converter/src/transaction_converter.rs:347-392`) — calls `class_manager_client.add_class(tx.contract_class).await?`, then checks `compiled_class_hash` against the returned `executable_class_hash_v2`. The class is stored before the check, but on mismatch the function returns an error; no subsequent write clears a slot that was set by the async call. [3](#0-2) 

4. **`perform_pre_validation_stage`** (`crates/blockifier/src/transaction/account_transaction.rs:355-372`) — increments the nonce via `handle_nonce`, then checks fees and proof facts. The nonce increment is inside a `CachedState` / `TransactionalState` that is never committed to persistent storage during gateway validation; it is discarded after the call. [4](#0-3) 

**Why no analog exists:** The Sequencer's state model uses layered

### Citations

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L599-623)
```rust
    fn concurrency_execute_fee_transfer<S: StateReader>(
        state: &mut TransactionalState<'_, S>,
        tx_context: Arc<TransactionContext>,
        actual_fee: Fee,
    ) -> TransactionExecutionResult<CallInfo> {
        let fee_address = tx_context.fee_token_address();
        let (sequencer_balance_key_low, sequencer_balance_key_high) =
            get_sequencer_balance_keys(&tx_context.block_context);
        let mut transfer_state = TransactionalState::create_transactional(state);

        // Set the initial sequencer balance to avoid tarnishing the read-set of the transaction.
        let cache = transfer_state.cache.get_mut();
        for key in [sequencer_balance_key_low, sequencer_balance_key_high] {
            cache.set_storage_initial_value(fee_address, key, Felt::ZERO);
        }

        let fee_transfer_call_info =
            Self::execute_fee_transfer(&mut transfer_state, tx_context, actual_fee);
        // Commit without updating the sequencer balance.
        let storage_writes = &mut transfer_state.cache.get_mut().writes.storage;
        storage_writes.remove(&(fee_address, sequencer_balance_key_low));
        storage_writes.remove(&(fee_address, sequencer_balance_key_high));
        transfer_state.commit();
        fee_transfer_call_info
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-460)
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
```

**File:** crates/apollo_transaction_converter/src/transaction_converter.rs (L347-392)
```rust
            RpcTransaction::Declare(RpcDeclareTransaction::V3(tx)) => {
                let ClassHashes { class_hash, executable_class_hash_v2 } =
                // TODO(Dori): Make this async and spawn a task to compile and add it to the class manager.
                    self.class_manager_client.add_class(tx.contract_class).await?;
                // TODO(Aviv): Ensure that we do not want to
                // allow declare with compiled class hash v1.
                if tx.compiled_class_hash != executable_class_hash_v2 {
                    return Err(TransactionConverterError::ValidateCompiledClassHashError(
                        ValidateCompiledClassHashError::CompiledClassHashMismatch {
                            computed_class_hash: executable_class_hash_v2,
                            supplied_class_hash: tx.compiled_class_hash,
                        },
                    ));
                }
                (
                    InternalRpcTransactionWithoutTxHash::Declare(InternalRpcDeclareTransactionV3 {
                        sender_address: tx.sender_address,
                        compiled_class_hash: tx.compiled_class_hash,
                        signature: tx.signature,
                        nonce: tx.nonce,
                        class_hash,
                        resource_bounds: tx.resource_bounds,
                        tip: tx.tip,
                        paymaster_data: tx.paymaster_data,
                        account_deployment_data: tx.account_deployment_data,
                        nonce_data_availability_mode: tx.nonce_data_availability_mode,
                        fee_data_availability_mode: tx.fee_data_availability_mode,
                    }),
                    None,
                )
            }
            RpcTransaction::DeployAccount(RpcDeployAccountTransaction::V3(tx)) => {
                let contract_address = tx.calculate_contract_address()?;
                (
                    InternalRpcTransactionWithoutTxHash::DeployAccount(
                        InternalRpcDeployAccountTransaction {
                            tx: RpcDeployAccountTransaction::V3(tx),
                            contract_address,
                        },
                    ),
                    None,
                )
            }
        };
        let tx_hash = tx_without_hash.calculate_transaction_hash(&self.chain_id)?;
        Ok((InternalRpcTransaction { tx: tx_without_hash, tx_hash }, proof_data))
```
