### Title
Gateway Admits Invoke Transaction Without Signature Verification After Deploy-Account Is Evicted From Mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway performs a one-time, point-in-time check to decide whether to skip the `__validate__` entry point (signature verification) for an invoke transaction with nonce=1. The condition it checks — that a deploy-account transaction exists in the mempool for the same address — can become stale after admission. When the deploy-account transaction is subsequently evicted from the mempool (due to capacity pressure or TTL expiry), the invoke transaction remains in the mempool without having undergone signature verification, and without any valid justification for that skip. This is the direct sequencer analog of the external report: a "canceled" (evicted) prerequisite transaction leaves a stale, unvalidated record that was admitted under a condition that no longer holds.

### Finding Description

The gateway's stateful validation path in `extract_state_nonce_and_run_validations` calls `run_pre_validation_checks`, which in turn calls `skip_stateful_validations`:

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When this returns `true`, `run_validate_entry_point` is called with `validate: false`, meaning the `__validate__` entry point (which verifies the transaction signature) is never invoked:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

The justification for skipping is that `account_tx_in_pool_or_recent_block` returns `true`, which the code comments explain means a deploy-account transaction must be in the mempool: [3](#0-2) 

However, `account_tx_in_pool_or_recent_block` checks for the presence of **any** transaction from that address in the pool, not specifically a deploy-account:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [4](#0-3) 

**The stale-record scenario:**

1. Attacker submits a `deploy_account` tx (nonce=0) for address A.
2. Attacker simultaneously submits an `invoke` tx (nonce=1) with a **fabricated/invalid signature** for address A.
3. Gateway: `account_nonce=0`, `tx_nonce=1`, `account_tx_in_pool_or_recent_block(A)=true` (deploy-account is in pool) → `skip_validate=true` → invoke tx admitted to mempool **without `__validate__`**.
4. The deploy-account tx is subsequently **evicted** from the mempool (capacity overflow evicts gap-account transactions via `try_make_space`, or TTL expiry via `remove_expired_txs`).
5. The invoke tx (with unverified/fake signature) **remains in the mempool**. The condition that justified skipping validation is gone, but there is no re-validation or invalidation of the invoke tx.
6. After eviction of the deploy-account, `tx_pool.contains_account(A)` still returns `true` because the invoke tx itself is still in the pool — meaning the stale admission record perpetuates itself. [5](#0-4) 

The eviction path removes the deploy-account from `tx_pool` but has no mechanism to re-validate or remove the invoke tx that was admitted under the now-invalid skip condition: [6](#0-5) 

### Impact Explanation

The gateway's admission invariant — "every transaction in the mempool has either passed `__validate__` or has a currently-valid justification for skipping it" — is broken. An invoke transaction with a fabricated signature is resident in the mempool without having undergone signature verification, and the condition that justified the skip (deploy-account in pool) is no longer true. In FIFO/Echonet mode, gap-account transactions are enqueued and can be picked up by the batcher, causing the batcher to attempt execution of a transaction whose signature was never verified at the gateway level. This matches the **High** impact: "Mempool/gateway/RPC admission accepts invalid transactions before sequencing."

### Likelihood Explanation

The trigger is fully unprivileged: any user can submit a deploy-account + invoke pair. The deploy-account eviction occurs naturally under capacity pressure (the mempool evicts gap-account transactions to make room for higher-priority ones) or TTL expiry. No privileged access or special conditions are required beyond normal network activity.

### Recommendation

After the deploy-account transaction is evicted from the mempool, the mempool should invalidate (remove) any associated invoke transactions that were admitted under the validation-skip condition. Concretely:

1. When `try_make_space` or `remove_expired_txs` evicts a deploy-account transaction, check whether any invoke transactions for the same address were admitted with `skip_validate=true` (i.e., nonce=1, admitted when account_nonce=0 and no on-chain account existed). If so, remove them as well.
2. Alternatively, tag transactions admitted via the skip path and re-validate them (run `__validate__`) when the deploy-account they depended on is removed from the pool.
3. At minimum, `account_tx_in_pool_or_recent_block` should distinguish between a deploy-account transaction and other transaction types when used as the justification for skipping signature verification.

### Proof of Concept

```
1. Attacker generates a fresh keypair and computes the counterfactual address A.
2. Attacker submits DeployAccount(nonce=0, address=A) to the gateway → accepted, enters mempool.
3. Attacker submits Invoke(nonce=1, sender=A, signature=[0xdead, 0xbeef]) to the gateway.
   - Gateway: account_nonce=0, tx_nonce=1, account_tx_in_pool_or_recent_block(A)=true
     → skip_stateful_validations returns true → __validate__ skipped → tx admitted.
4. Attacker fills the mempool with many high-tip transactions from other addresses.
   - Mempool capacity overflows; try_make_space evicts the DeployAccount (gap account).
5. Invoke(nonce=1, fake_sig) remains in the mempool.
   - account_tx_in_pool_or_recent_block(A) still returns true (invoke tx is in pool).
   - No re-validation is triggered.
6. In FIFO/Echonet mode: batcher calls get_txs, receives the invoke tx, attempts execution.
   - Account A does not exist on-chain → execution fails / tx reverts.
   - The batcher processed a transaction whose signature was never verified at the gateway.
``` [7](#0-6) [8](#0-7)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L310-312)
```rust
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L849-866)
```rust
    fn remove_expired_txs(&mut self) -> AddressToNonce {
        let removed_txs = self
            .tx_pool
            .remove_txs_older_than(self.config.dynamic_config.transaction_ttl, &self.state.staged);

        for tx_ref in &removed_txs {
            self.decrement_stuck_txs_if_gap_account(tx_ref.address, 1);
        }

        let queued_txs = self.tx_queue.remove_txs(&removed_txs);

        self.log_and_count_expired_txs(&removed_txs);
        self.update_state_metrics();
        queued_txs
            .into_iter()
            .map(|tx| (tx.address, self.state.resolve_nonce(tx.address, tx.nonce)))
            .collect::<AddressToNonce>()
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L990-1020)
```rust
    // Attempts to make space for a new transaction by evicting existing transactions.
    // Returns true if enough space was freed, false otherwise.
    pub fn try_make_space(&mut self, required_space: u64) -> bool {
        let mut total_space_freed = 0;
        let mut evicted_txs = Vec::new();

        while total_space_freed < required_space {
            let Some(address) = self.get_evictable_account() else {
                break;
            };

            let txs: Vec<_> = self.tx_pool.account_txs_sorted_by_nonce(address).copied().collect();
            for tx_ref in txs.iter().rev() {
                let tx = self
                    .tx_pool
                    .remove(tx_ref.tx_hash)
                    .expect("Transaction must exist in the pool.");
                total_space_freed += tx.total_bytes();
                evicted_txs.push(*tx_ref);
                metric_count_evicted_txs(1);
                self.decrement_stuck_txs_if_gap_account(address, 1);
                if total_space_freed >= required_space {
                    break;
                }
            }

            // Clean up if account is now empty.
            if !self.tx_pool.contains_account(address) {
                self.accounts_with_gap.swap_remove(&address);
            }
        }
```

**File:** crates/apollo_gateway/src/gateway.rs (L253-266)
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
```
