### Title
`skip_stateful_validations` Allows Signature-Bypassed Invoke Transactions to Enter Mempool via deploy_account UX Feature - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function unconditionally skips the `__validate__` entry-point (signature verification) for any Invoke transaction with `nonce == 1` from an account whose on-chain nonce is `0`, provided `account_tx_in_pool_or_recent_block` returns `true`. An unprivileged attacker can satisfy that condition for any address that has a pending `deploy_account` in the mempool, then submit an Invoke with an arbitrary/invalid signature that the gateway accepts without calling `__validate__`. The transaction enters the mempool and is only rejected later during batcher execution, constituting a gateway admission bypass.

### Finding Description

**Outer validation layer — gateway stateful path**

`StatefulTransactionValidator::extract_state_nonce_and_run_validations` calls `run_pre_validation_checks`, which calls `skip_stateful_validations`: [1](#0-0) 

`skip_stateful_validations` returns `true` (skip) when all three conditions hold: [2](#0-1) 

When `skip_validate == true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags`, so `StatefulValidator::perform_validations` returns `Ok(())` before ever calling `__validate__`: [3](#0-2) 

Inside `StatefulValidator::perform_validations`, the early return on `!validate` is explicit: [4](#0-3) 

**The broken invariant**

The code comment claims: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."*

`account_tx_in_pool_or_recent_block` is implemented as: [5](#0-4) 

It returns `true` if the address appears in `tx_pool` (any transaction) **or** in `state` (staged/committed). An attacker who observes a legitimate user's `deploy_account` for address `X` in the mempool can immediately submit an Invoke from `X` with `nonce=1` and a completely invalid signature. The gateway sees `account_tx_in_pool_or_recent_block(X) == true`, skips `__validate__`, and admits the transaction.

**Attack path (unprivileged, no key material for X)**

1. Legitimate user broadcasts `deploy_account` for address `X`; it enters the mempool.
2. Attacker crafts `Invoke(sender=X, nonce=1, signature=[0xdead, 0xbeef])`.
3. Gateway stateless checks pass (nonce in `[0, 200]`, resource bounds non-zero, etc.).
4. `skip_stateful_validations` fires: `tx.nonce()==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(X)==true` → returns `true`.
5. `run_validate_entry_point` sets `validate=false`; `__validate__` is never called; gateway returns `Ok`.
6. Transaction is forwarded to the mempool via `mempool_client.add_tx(...)`. [6](#0-5) 

7. Batcher later pulls the transaction, creates a fresh `AccountTransaction` with `validate=true`, calls `__validate__`, which fails (invalid signature). Transaction is rejected at execution time.

### Impact Explanation

The gateway admits an Invoke transaction whose signature has never been verified. The transaction occupies a mempool slot and consumes gateway/mempool processing resources. An attacker monitoring the public mempool can flood it with invalid Invoke transactions for every address that has a pending `deploy_account`, constituting a targeted DoS against the mempool admission path. This matches: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

The mempool is public; `deploy_account` transactions are visible to anyone. The attack requires no privileged access, no key material, and no on-chain interaction. The only prerequisite is that a `deploy_account` for the target address is in the mempool, which is the normal state during account creation. The `max_nonce_for_validation_skip` default is `0x1`, so the window is exactly nonce=1, but that is the most common post-deploy nonce. [7](#0-6) 

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a check that specifically confirms a `deploy_account` transaction (not just any transaction) is pending for the address. Alternatively, restrict the skip to cases where the gateway itself received the `deploy_account` in the same submission batch (i.e., track the pairing explicitly rather than relying on a mempool presence query that is satisfied by any transaction type).

### Proof of Concept

```
# Prerequisites: mempool is running; address X has a pending deploy_account.

# Step 1 – observe X in mempool (public information).

# Step 2 – craft invalid invoke:
invoke_tx = InvokeV3(
    sender_address = X,
    nonce          = 1,          # triggers skip_stateful_validations
    signature      = [0xdead],   # invalid
    resource_bounds = <valid>,
    calldata        = <arbitrary>,
)

# Step 3 – submit to gateway add_transaction endpoint.
# Expected: gateway returns success (tx_hash), transaction enters mempool.
# Actual __validate__ call: deferred to batcher, which rejects it.
```

The test case `should_skip_validation` in the existing test suite already confirms the gateway skips validation under exactly these conditions: [8](#0-7)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-314)
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-95)
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
        }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_gateway/src/gateway.rs (L253-286)
```rust
        let (internal_tx, executable_tx, proof_data) =
            self.convert_rpc_tx_to_internal_and_executable_txs(tx, &tx_signature).await?;
        drop(compilation_permit);

        let mut stateful_transaction_validator = self
            .stateful_tx_validator_factory
            .instantiate_validator(self.config.dynamic_config.native_classes_whitelist.clone())
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

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

**File:** crates/apollo_gateway_config/src/config.rs (L289-299)
```rust
impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
            min_gas_price_percentage: 100,
            versioned_constants_overrides: None,
        }
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator_test.rs (L151-157)
```rust
#[rstest]
#[case::should_skip_validation(
    executable_invoke_tx(invoke_tx_args!(nonce: nonce!(1))),
    nonce!(0),
    true,
    false
)]
```
