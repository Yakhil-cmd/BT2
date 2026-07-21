### Title
Gateway Admits Invoke Transaction Without `__validate__` Based on a Transiently-Present Deploy-Account That Can Be Evicted Before Execution - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function admits an invoke transaction (nonce=1, account_nonce=0) to the mempool without running the account's `__validate__` entry point, relying solely on the presence of a deploy-account transaction in the mempool at admission time. Because the mempool has no dependency-tracking between the deploy-account and the invoke transaction, the deploy-account can be evicted (TTL, capacity pressure, or fee-escalation replacement) after the invoke is admitted. The invoke transaction then sits in the mempool with its signature permanently unverified and will fail at execution time, while the gateway has already returned a success response to the submitter.

### Finding Description

**Admission path (the "resource" is checked once and never re-checked):**

`skip_stateful_validations` returns `true` — causing `run_validate_entry_point` to set `validate: false` and skip the `__validate__` call — when all three conditions hold simultaneously:

1. The transaction is an Invoke with `tx.nonce() == Nonce(Felt::ONE)`
2. The on-chain account nonce is `Nonce(Felt::ZERO)` (account not yet deployed)
3. `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true` [1](#0-0) 

Condition 3 is satisfied as long as the deploy-account transaction is in the pool at the moment the invoke is submitted: [2](#0-1) 

**The resource is released without invalidating the commitment:**

The mempool evicts transactions due to TTL expiry, capacity pressure, or fee-escalation replacement. None of these eviction paths check whether the evicted transaction is a deploy-account that a skip-validated invoke depends on, and none of them cascade-evict the dependent invoke transaction. [3](#0-2) 

After the deploy-account is evicted, `account_tx_in_pool_or_recent_block` returns `false` for the address, but the invoke transaction is already in the pool. The mempool's gap-tracking marks the account as having a nonce gap (lowest pool nonce = 1 > account nonce = 0), but the transaction is not removed: [4](#0-3) 

**Execution-time failure:**

When the batcher eventually picks up the stuck invoke transaction, `perform_pre_validation_stage` runs. If the account has no balance (it was never deployed), `verify_can_pay_committed_bounds` fails. If resource bounds are zero (`charge_fee = false`), execution proceeds to `run_or_revert`, which calls `__validate__` on a non-existent account and fails. In both cases the transaction is rejected at execution time — after the gateway already accepted it. [5](#0-4) [6](#0-5) 

**Exact broken invariant (analog to the external report):**

| External report | Sequencer analog |
|---|---|
| `totalCoverTokens` decremented when policy expires | deploy-account evicted from mempool |
| Claim can be filed within grace period | invoke tx admitted via `skip_stateful_validations` |
| Funds withdrawn before claim is processed | deploy-account evicted before invoke is executed |
| Claim fails | invoke tx fails at execution time |

The invariant broken: *a transaction admitted to the mempool via the skip-validate path carries an implicit precondition (the deploy-account must be committed before the invoke is executed) that is never enforced after admission.*

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

The gateway returns a success response for an invoke transaction whose `__validate__` entry point has never been called and whose account may never be deployed. The transaction occupies mempool space indefinitely (until TTL expiry) and will fail at execution time, wasting batcher resources. An attacker can deliberately trigger this by submitting a deploy-account, immediately submitting an invoke with nonce=1 (admitted via skip-validate), then fee-escalating or replacing the deploy-account to cause its eviction, leaving the invoke stranded.

### Likelihood Explanation

The scenario arises naturally under mempool pressure (capacity eviction) or deliberately via fee escalation. The skip-validate path is an intentional production feature used in the standard deploy-account + invoke UX flow, so it is exercised on every new account deployment. Any user can trigger the condition without elevated privileges.

### Recommendation

When a deploy-account transaction is evicted from the mempool (for any reason), the mempool should also evict any pending invoke transactions for the same address that were admitted via the skip-validate path (i.e., those with nonce=1 and no committed nonce for the address). Alternatively, when `account_tx_in_pool_or_recent_block` transitions from `true` to `false` for an address with account_nonce=0, all pool transactions for that address with nonce ≥ 1 should be removed.

A lighter-weight alternative is to re-check `account_tx_in_pool_

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-458)
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
```

**File:** crates/apollo_mempool/src/mempool.rs (L619-695)
```rust
    fn add_ready_declares(&mut self) {
        let now = self.clock.now();
        while let Some((submission_time, _args)) = self.delayed_declares.front() {
            if now - self.config.static_config.declare_delay < *submission_time {
                break;
            }
            let (_submission_time, args) =
                self.delayed_declares.pop_front().expect("Delay declare should exist.");
            self.add_tx_inner(args);
        }
        self.update_state_metrics();
    }

    /// Update the mempool's internal state according to the committed block (resolves nonce gaps,
    /// updates account balances).
    #[instrument(skip(self, args))]
    pub fn commit_block(&mut self, args: CommitBlockArgs) {
        let CommitBlockArgs { address_to_nonce, rejected_tx_hashes } = args;
        debug!(
            "Committing block with {} addresses and {} rejected tx to the mempool.",
            address_to_nonce.len(),
            rejected_tx_hashes.len()
        );

        let mut committed_nonce_updates = AddressToNonce::new();
        // Align mempool data to committed nonces.
        for (&address, &next_nonce) in &address_to_nonce {
            self.validate_commitment(address, next_nonce);
            committed_nonce_updates.insert(address, next_nonce);

            // Remove out-of-date transactions, if any.
            // Note: In FIFO mode, get_nonce returns None (committed txs were already popped from
            // queue during get_txs), so this cleanup is skipped.
            if self
                .tx_queue
                .get_nonce(address)
                .is_some_and(|queued_nonce| queued_nonce != next_nonce)
            {
                assert!(
                    self.tx_queue.remove_by_address(address),
                    "Expected to remove address from queue."
                );
            }

            // Remove from pool.
            let n_removed_txs = self.tx_pool.remove_up_to_nonce_when_committed(address, next_nonce);
            metric_count_committed_txs(n_removed_txs);
            self.decrement_stuck_txs_if_gap_account(address, n_removed_txs);

            // Close nonce gap, if exists.
            // In FIFO mode, we handle gap filling when rewinding transactions.
            if !self.is_fifo() && self.tx_queue.get_nonce(address).is_none() {
                if let Some(tx_reference) =
                    self.tx_pool.get_by_address_and_nonce(address, next_nonce)
                {
                    self.insert_to_tx_queue(tx_reference);
                }
            }
        }

        // Commit block and rewind nonces of addresses that were not included in block.
        let addresses_to_rewind = self.state.commit(address_to_nonce.clone());

        let rewound_tx_hashes =
            self.rewind_txs(addresses_to_rewind, &address_to_nonce, &rejected_tx_hashes);
        debug!("Aligned mempool to committed nonces.");

        // Remove rejected transactions from the mempool.
        let mut account_nonce_updates =
            self.remove_rejected_txs(rejected_tx_hashes, &rewound_tx_hashes);

        // Committed nonces should overwrite rejected transactions.
        account_nonce_updates.extend(committed_nonce_updates);

        self.update_accounts_with_gap(account_nonce_updates);
        self.update_state_metrics();
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L947-978)
```rust
    fn update_accounts_with_gap(&mut self, address_to_nonce: AddressToNonce) {
        for (address, account_nonce) in address_to_nonce {
            // If a delayed declare transaction exists at the account nonce, it is next to execute,
            // so no gap exists.
            if self.delayed_declares.contains(address, account_nonce) {
                self.remove_from_accounts_with_gap(address);
                continue;
            }

            // Gap exists when lowest transaction nonce is higher than account nonce.
            let gap_exists = match self.tx_pool.get_lowest_nonce(address) {
                Some(lowest_nonce) => account_nonce < lowest_nonce,
                None => false, // No transactions for the account, so no gap.
            };

            // Update the eviction tracking set accordingly.
            if gap_exists {
                if self.accounts_with_gap.insert(address) {
                    // Newly entered gap: all current pool txs for this account are now stuck.
                    let n_stuck = self.tx_pool.n_txs_for_address(address);
                    self.n_stuck_txs += n_stuck;
                    warn!(
                        "Account {address} has a nonce gap; {n_stuck} transaction(s) are now \
                         stuck."
                    );
                }
                // Stayed in gap: per-tx deltas were already applied at add/remove sites.
            } else {
                // Left gap: remaining pool txs for this account are no longer stuck.
                self.remove_from_accounts_with_gap(address);
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
