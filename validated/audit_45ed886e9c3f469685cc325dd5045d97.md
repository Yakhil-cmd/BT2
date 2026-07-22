### Title
`skip_stateful_validations` accepts any mempool-present account as a deploy-account proxy, allowing signature-bypassed invoke transactions with nonce=1 to enter the mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function is designed to skip the `__validate__` entry point for invoke transactions with nonce=1 when the account has a pending `deploy_account` in the mempool (a UX improvement for the deploy-account + invoke flow). However, the guard uses `account_tx_in_pool_or_recent_block`, which returns `true` if the account has **any** transaction in the pool or any recent committed block — not exclusively a `deploy_account`. For accounts that exist on-chain with nonce=0 (deployed via the `deploy` syscall rather than a `deploy_account` transaction), a legitimate invoke with nonce=0 can already be in the mempool. An attacker who observes this can immediately submit a second invoke with nonce=1 carrying an **arbitrary/invalid signature**, and the gateway will accept it into the mempool without running `__validate__`.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` fires when all four conditions hold:

1. The incoming transaction is `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (on-chain state).
4. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [1](#0-0) 

When all four hold, `run_validate_entry_point` is called with `skip_validate = true`, which sets `execution_flags.validate = false`, causing the blockifier's `StatefulValidator::perform_validations` to return `Ok(())` without ever calling `__validate__`: [2](#0-1) [3](#0-2) 

The comment in `skip_stateful_validations` asserts: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* This reasoning is incorrect. `account_tx_in_pool_or_recent_block` is implemented as: [4](#0-3) 

`state.contains_account` returns `true` if the address appears in the mempool's committed or staged nonce map — populated by **any** transaction type, not only `deploy_account`. `tx_pool.contains_account` similarly returns `true` for any pooled transaction from that address. [5](#0-4) 

An account deployed via the `deploy` syscall (not `deploy_account`) exists on-chain with nonce=0. Its owner can legitimately submit an invoke with nonce=0, which passes `validate_nonce` (the range check `0 ≤ 0 ≤ max_allowed_nonce_gap` succeeds) and passes `__validate__` (the account has code). Once that invoke is in the pool, `account_tx_in_pool_or_recent_block` returns `true` for that address. Any third party can now submit an invoke with nonce=1 carrying a garbage signature; `validate_state_preconditions` and `validate_by_mempool` both pass (nonce=1 is within the allowed gap, no duplicate), `skip_stateful_validations` returns `true`, and the gateway forwards the unauthenticated transaction to the mempool via `mempool_client.add_tx`. [6](#0-5) [7](#0-6) 

The mempool's own `validate_tx` only checks for duplicate hashes and nonce ordering — it does not verify signatures: [8](#0-7) 

### Impact Explanation

Invalid (unauthenticated) invoke transactions with nonce=1 are admitted into the mempool without signature verification. The batcher will later attempt to execute them with `validate: true` (set by `AccountTransaction::new_for_sequencing`): [9](#0-8) 

Execution will fail at `__validate__`, and the batcher will mark the transaction as rejected. However, the attacker can continuously flood the mempool with such transactions for any qualifying account, consuming mempool capacity, batcher CPU, and block-proposal bandwidth. This matches the **High** impact: *"Mempool/gateway/RPC admission accepts invalid transactions before sequencing."*

### Likelihood Explanation

The precondition — an account with on-chain nonce=0 that has any transaction in the mempool — is reachable without any privileged access. Accounts deployed via the `deploy` syscall (e.g., factory-deployed wallets) start with nonce=0 and may have pending invokes. The attacker only needs to observe the mempool (public) and submit a crafted invoke; no private key or special role is required.

### Recommendation

The skip logic must be restricted to the case where the account genuinely does not yet exist on-chain. Two complementary fixes:

1. **Check account existence, not just mempool presence.** Before skipping, verify that the account has no deployed class hash on-chain (i.e., `get_class_hash_at(sender_address) == UNINITIALIZED_CLASS_HASH`). If the account already has code, `__validate__` can and must be called.

2. **Track deploy-account transactions specifically.** Add a dedicated mempool API (e.g., `has_pending_deploy_account(address)`) that returns `true` only when a `deploy_account` transaction for that address is in the pool, rather than reusing the generic `account_tx_in_pool_or_recent_block` predicate.

### Proof of Concept

```
1. Deploy contract C at address A via the `deploy` syscall (not deploy_account).
   → A exists on-chain, class_hash ≠ 0, nonce = 0.

2. Owner of A submits InvokeV3(sender=A, nonce=0, valid_signature).
   → Passes stateless checks, validate_nonce (0 ≤ 0), __validate__ succeeds.
   → Transaction T0 enters the mempool.
   → account_tx_in_pool_or_recent_block(A) now returns true.

3. Attacker submits InvokeV3(sender=A, nonce=1, signature=[0xdead, 0xbeef]).
   → Stateless checks pass (signature length ≤ max).
   → validate_nonce: account_nonce=0, tx_nonce=1, 0 ≤ 1 ≤ max_allowed_nonce_gap → OK.
   → validate_by_mempool: nonce 1 ≥ 0, no duplicate → OK.
   → skip_stateful_validations: Invoke, nonce==1, account_nonce==0,
     account_tx_in_pool_or_recent_block(A)==true → returns true.
   → run_validate_entry_point called with skip_validate=true → __validate__ NOT called.
   → Transaction T1 (invalid signature) forwarded to mempool.add_tx → accepted.

4. Batcher calls get_txs, receives T1, attempts execute_raw with validate=true.
   → __validate__ runs, signature check fails → transaction rejected.
   → Attacker repeats step 3 indefinitely with fresh nonces/hashes.
``` [10](#0-9) [4](#0-3) [11](#0-10)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-312)
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

**File:** crates/apollo_gateway/src/gateway.rs (L263-293)
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
        match mempool_client_result_to_deprecated_gw_result(&tx_signature, mempool_client_result) {
            Ok(()) => {}
            Err(e) => {
                metric_counters.record_add_tx_failure(&e);
                return Err(e);
            }
        };
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
