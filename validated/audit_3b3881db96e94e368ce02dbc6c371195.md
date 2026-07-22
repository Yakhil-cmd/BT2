### Title
Gateway Signature Validation Bypass via `skip_stateful_validations` for Invoke Transactions with Nonce 1 — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator uses `account_tx_in_pool_or_recent_block` as a proxy for "a deploy_account transaction exists in the mempool for this sender." However, that check returns `true` for **any** transaction from the address in the pool, not exclusively a deploy_account. An unprivileged attacker who observes a legitimate deploy_account transaction for address A in the mempool can submit an invoke transaction with nonce 1 from address A carrying an arbitrary/invalid signature, and the gateway will admit it to the mempool without ever calling the account's `__validate__` entry point.

### Finding Description

In `add_tx_inner` the gateway calls `extract_state_nonce_and_run_validations`, which internally calls `run_pre_validation_checks` and then `run_validate_entry_point`. [1](#0-0) 

`run_pre_validation_checks` calls `skip_stateful_validations`: [2](#0-1) 

`skip_stateful_validations` returns `true` (skip `__validate__`) when the transaction is an Invoke with `tx.nonce() == 1` AND `account_nonce == 0` AND `account_tx_in_pool_or_recent_block` returns `true`: [3](#0-2) 

The comment claims this is sufficient because the account "either has a deploy_account transaction or transactions with future nonces that passed validations." But `account_tx_in_pool_or_recent_block` is implemented as: [4](#0-3) 

It returns `true` if **any** transaction from that address is in the pool — including a deploy_account submitted by a completely different party (the legitimate user). It does not verify that the pooled transaction is specifically a deploy_account, nor that the caller of `skip_stateful_validations` is the same party who submitted the deploy_account.

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `validate = false`: [5](#0-4) 

Inside `StatefulValidator::perform_validations`, when `validate = false` the function returns `Ok(())` immediately after `perform_pre_validation_stage`, without ever calling the account's `__validate__` entry point: [6](#0-5) 

`perform_pre_validation_stage` only checks nonce, fee bounds, balance, and proof facts — it does not verify the transaction signature: [7](#0-6) 

### Impact Explanation

An attacker can inject an invoke transaction carrying an arbitrary/forged signature into the mempool for any pre-funded account that has a pending deploy_account transaction. The gateway's only signature-verification mechanism (`__validate__`) is completely bypassed. The invalid transaction occupies a mempool slot, is forwarded to the batcher, and will fail during execution — but it was admitted without authorization. This satisfies the **High** impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

Secondary effects:
- Mempool slot exhaustion / DoS against the legitimate user's nonce-1 invoke (the attacker's invalid transaction occupies the (address, nonce=1) slot, forcing the legitimate user to perform fee escalation or wait for eviction).
- Batcher CPU waste executing a transaction that will always revert at `__validate__`.

### Likelihood Explanation

The attack requires only:
1. Observing the public mempool for a deploy_account transaction targeting a pre-funded address (trivially observable via the gateway's public API or P2P gossip).
2. Constructing an invoke transaction with `nonce = 1`, `sender_address = A`, and any signature bytes.
3. Submitting it to the gateway before the deploy_account is committed.

No privileged access, no special knowledge, and no cryptographic capability is required. The window is the entire time the deploy_account sits in the mempool (potentially many blocks).

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **deploy_account** transaction for the sender address is present in the pool. Alternatively, expose a dedicated `deploy_account_in_pool(address)` query on the mempool that only returns `true` when the pooled transaction is of type `DeployAccount`. This closes the bypass while preserving the intended UX for simultaneous deploy_account + invoke submission.

### Proof of Concept

1. Legitimate user pre-funds address `A` and submits `DeployAccountV3` for `A` (nonce 0). The gateway admits it; the mempool now has `tx_pool.contains_account(A) == true`.

2. Attacker calls `add_tx` with:
   ```
   InvokeV3 {
       sender_address: A,
       nonce: 1,
       signature: [0xdead, 0xbeef],   // arbitrary garbage
       resource_bounds: { l2_gas: { max_amount: 1, max_price_per_unit: min_gas_price } },
       calldata: [],
       ...
   }
   ```

3. Gateway flow:
   - `check_declare_permissions` → not a declare, passes.
   - `stateless_tx_validator.validate` → resource bounds non-zero, size within limits, passes. [8](#0-7) 
   - `convert_rpc_tx_to_internal_and_executable_txs` → no signature check, passes.
   - `get_nonce_from_state(A)` → returns `Nonce(0)` (account not yet deployed).
   - `validate_nonce` → `0 ≤ 1 ≤ 0 + max_gap`, passes.
   - `validate_by_mempool` → no duplicate hash, nonce in range, passes.
   - `skip_stateful_validations`: `tx.nonce() == 1 && account_nonce == 0` → calls `account_tx_in_pool_or_recent_block(A)` → returns `true` (deploy_account is in pool) → returns `true` (skip validation). [9](#0-8) 
   - `run_validate_entry_point(skip_validate=true)` → `validate = false` → `__validate__` never called → `Ok(())`.

4. The invalid invoke with garbage signature is forwarded to the mempool and accepted. [10](#0-9)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-314)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L33-54)
```rust
    pub fn validate(&self, tx: &RpcTransaction) -> StatelessTransactionValidatorResult<()> {
        // TODO(Arni, 1/5/2024): Add a mechanism that validate the sender address is not blocked.
        // TODO(Arni, 1/5/2024): Validate transaction version.

        Self::validate_contract_address(tx)?;
        Self::validate_empty_account_deployment_data(tx)?;
        Self::validate_empty_paymaster_data(tx)?;
        self.validate_resource_bounds(tx)?;
        self.validate_tx_size(tx)?;
        self.validate_nonce_data_availability_mode(tx)?;
        self.validate_fee_data_availability_mode(tx)?;

        if let RpcTransaction::Invoke(invoke_tx) = tx {
            self.validate_client_side_proving_allowed(invoke_tx)?;
            self.validate_proof_facts_and_proof_consistency(invoke_tx)?;
        }

        if let RpcTransaction::Declare(declare_tx) = tx {
            self.validate_declare_tx(declare_tx)?;
        }
        Ok(())
    }
```

**File:** crates/apollo_gateway/src/gateway.rs (L263-286)
```rust
        let nonce = stateful_transaction_validator
            .extract_state_nonce_and_run_validations(&executable_tx, self.mempool_client.clone())
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let proof_archive_handle = self
            .store_proof_and_spawn_archiving(proof_data, internal_tx.tx_hash, is_p2p)
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let gateway_output = create_gateway_output(&internal_tx);

        let add_tx_args = AddTransactionArgsWrapper {
            args: AddTransactionArgs::new(internal_tx, nonce),
            p2p_message_metadata,
        };

        // Await as late as possible for proof archiving before sending the transaction to the
        // mempool.
        Self::await_proof_archiving(proof_archive_handle)
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let mempool_client_result = self.mempool_client.add_tx(add_tx_args).await;
```
