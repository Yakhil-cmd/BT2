### Title
Gateway Admits Invoke Transaction Without Signature Verification via TOCTOU in `skip_stateful_validations` — (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary
The `skip_stateful_validations` function skips the `__validate__` entry-point call (i.e., signature verification) for an invoke transaction with nonce=1 when a deploy-account transaction is present in the mempool at admission time. Because the deploy-account transaction can be removed from the mempool after the invoke transaction is admitted (TTL expiry, capacity eviction, or fee-escalation replacement), the invoke transaction remains in the mempool with its signature permanently unverified. This is a TOCTOU admission-control failure: the gateway's "deploy-account is present" check is valid at the moment of the check but is not re-evaluated before execution, allowing an attacker to inject invoke transactions with arbitrary (invalid) signatures into the mempool at zero cost.

### Finding Description

**Root cause — `skip_stateful_validations`** [1](#0-0) 

When an invoke transaction arrives with `tx.nonce() == 1` and the on-chain account nonce is `0`, the gateway calls `account_tx_in_pool_or_recent_block`. If that returns `true`, `skip_stateful_validations` returns `true`, and `run_validate_entry_point` is called with `validate: false`: [2](#0-1) 

This means `StatefulValidator::perform_validations` reaches the branch: [3](#0-2) 

…and returns `Ok(())` without ever calling `__validate__`. The transaction is then forwarded to the mempool with its signature unchecked.

**TOCTOU window**

`account_tx_in_pool_or_recent_block` is a point-in-time snapshot: [4](#0-3) 

After the invoke transaction is admitted, the deploy-account transaction that justified the skip can be removed by:

1. **TTL expiry** — `remove_expired_txs` silently drops transactions older than `transaction_ttl`: [5](#0-4) 

2. **Capacity eviction** — `try_make_space` evicts gap-account transactions: [6](#0-5) 

3. **Fee-escalation replacement** — a higher-fee deploy-account replaces the original, and the replacement can itself expire.

Once the deploy-account is gone, the invoke transaction remains in the mempool with its signature never verified.

**Execution outcome**

When the batcher later pulls the invoke transaction and calls `execute_raw`, `perform_pre_validation_stage` runs with `strict_nonce_check = true`: [7](#0-6) 

Because the account was never deployed (nonce still 0), `handle_nonce` fails with `InvalidNonce`. This is a pre-validation error — the transaction is **rejected**, not reverted, so **no fee is charged to the attacker**.

### Impact Explanation

The gateway makes a wrong admission decision: it accepts an invoke transaction whose `__validate__` entry point (signature check) has never been executed and will never be executed before the transaction is either rejected or reverted. An attacker can:

1. Submit a deploy-account transaction (no execution required, no fee charged at submission).
2. Immediately submit an invoke transaction with nonce=1 and an **arbitrary/invalid signature** — the gateway skips `__validate__` because the deploy-account is in the pool.
3. Wait for the deploy-account to expire (TTL).
4. The invoke transaction fails with `InvalidNonce` at execution time — **no fee charged**.
5. Repeat indefinitely to flood the mempool with signature-unverified transactions.

This matches: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

The attack requires no privileges. Any user can submit transactions to the gateway. The only precondition is that the deploy-account transaction must be in the mempool at the moment the invoke transaction is submitted, which the attacker fully controls. The TTL window is configurable but finite, making the expiry reliable. The nonce=1 restriction limits the attack to one invoke transaction per fresh account address, but account addresses are cheap to generate.

### Recommendation

1. **Invalidate the skip on deploy-account removal**: When a deploy-account transaction is removed from the mempool (TTL, eviction, replacement), scan for and remove any associated nonce=1 invoke transactions that were admitted under the skip.
2. **Re-validate before batching**: In `get_txs`, re-check `account_tx_in_pool_or_recent_block` for any invoke transaction that was admitted with `skip_validate=true`; if the deploy-account is no longer present, drop the invoke transaction before returning it to the batcher.
3. **Tighten the skip condition**: Only skip `__validate__` if the deploy-account transaction is still present in the pool at the moment the invoke transaction is about to be forwarded to the mempool (i.e., hold the mempool lock across both checks).

### Proof of Concept

```
1. Attacker generates a fresh account address A (no on-chain state, nonce = 0).

2. Attacker submits deploy_account_tx for address A to the gateway.
   → deploy_account_tx enters the mempool (tx_pool.contains_account(A) = true).

3. Attacker submits invoke_tx(sender=A, nonce=1, signature=GARBAGE) to the gateway.
   → extract_state_nonce_and_run_validations:
       account_nonce = 0  (A not deployed)
       skip_stateful_validations: nonce==1 && account_nonce==0 && account_tx_in_pool_or_recent_block(A)==true
       → returns true (skip __validate__)
   → run_validate_entry_point called with validate=false → no __validate__ call
   → invoke_tx admitted to mempool with GARBAGE signature, unverified.

4. Attacker waits transaction_ttl seconds.
   → remove_expired_txs() removes deploy_account_tx from the pool.
   → account_tx_in_pool_or_recent_block(A) now returns false.
   → invoke_tx (GARBAGE signature) remains in the mempool.

5. Batcher calls get_txs(), receives invoke_tx.
   → execute_raw → perform_pre_validation_stage(strict_nonce_check=true)
   → handle_nonce: account_nonce=0, incoming=1, strict → InvalidNonce
   → transaction REJECTED, zero fee charged to attacker.

6. Attacker repeats from step 1 with a new address.
   Cost per cycle: zero (no transaction ever executes, no fee ever charged).
``` [8](#0-7) [9](#0-8) [10](#0-9)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-312)
```rust
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
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

**File:** crates/apollo_mempool/src/mempool.rs (L992-1020)
```rust
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
