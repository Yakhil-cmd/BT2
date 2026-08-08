### Title
Legitimate `Merge` instruction between reward calculation and partitioned distribution triggers `assert_eq!` panic in `build_updated_stake_reward` - ([File: runtime/src/bank/partitioned_epoch_rewards/distribution.rs])

### Summary
`build_updated_stake_reward` computes `expected_delegation` from the *live* stake account state read from `stakes_cache_accounts` at distribution time, then asserts it equals `new_stake.delegation.stake`, a value computed once during the epoch-boundary calculation phase and cached for the entire multi-block distribution window. An unprivileged staker who owns two active stake accounts delegated to the same vote account can call the native `Merge` instruction on their own accounts between the calculation slot and the slot at which that account's reward partition is distributed, changing the live `delegation.stake` and desynchronizing it from the cached calculation, which fires the `assert_eq!` and panics every honest validator simultaneously.

### Finding Description
Reward calculation happens once per epoch boundary in `process_new_epoch` → `begin_partitioned_rewards` → `calculate_rewards_for_partitioning`, which snapshots stake delegations via `self.stakes_cache.stakes()` and caches the resulting `PartitionedStakeReward` list (`epoch_rewards_calculation_cache`) for use across all subsequent distribution blocks. [1](#0-0) 

Distribution of these cached rewards happens over many subsequent blocks/partitions via `store_stake_accounts_in_partition`, which calls `build_updated_stake_reward` for each stake pubkey using the *current* live stakes cache, not the snapshot used for calculation. [2](#0-1) 

Inside `build_updated_stake_reward`, when `adjust_delegations_for_rent` is `false` (i.e., the `relax_post_exec_min_balance_check` feature is not active), the code computes `expected_delegation` from the *live* `stake.delegation.stake` plus the cached reward amount, and asserts it equals the cached `new_stake.delegation.stake` from the calculation phase: [3](#0-2) 

Between the calculation slot and this account's specific distribution partition slot, ordinary transactions are applied to the live `StakesCache` via `update_stakes_cache` → `check_and_store`, which re-derives the delegation from the account's on-chain data after every successful transaction. [4](#0-3) [5](#0-4) 

An unprivileged attacker who is the staker/withdraw authority of two fully-active stake accounts (A and B) delegated to the same vote account can, after the calculation phase for a given epoch has run (and A has been assigned a non-zero cached reward for the current epoch's distribution) but before A's specific partition index is processed by `store_stake_accounts_in_partition`, submit a `Merge` instruction merging B into A. `Merge` is a normal, unprivileged native stake-program instruction the attacker can invoke via CPI/system on accounts they fully own. [6](#0-5) 

This legitimately increases A's live `delegation.stake` by B's stake amount. When A's partition is later processed, `stake.delegation.stake` (line 285-287, live) now includes the merged amount, so `expected_delegation = live_stake + cached_reward` no longer equals the cached `new_stake.delegation.stake = old_stake + cached_reward`, and the `assert_eq!` fires, panicking the validator. Because reward calculation and the feature-set values (including `relax_post_exec_min_balance_check`) are part of consensus-relevant bank state and thus identical across all honest validators processing the same slot, this panic is fully deterministic and triggers on every honest node simultaneously.

No existing guard prevents this: `Merge` only checks that source/destination are compatible for merging (same voter, compatible activation state) — it does not check for or block pending reward distributions, and `build_updated_stake_reward` has no re-validation or graceful-degradation path for a delegation change; it only distinguishes `AccountNotFound` (fully closed account) from a live but mutated one.

### Impact Explanation
This is a cluster-wide, simultaneous validator panic at epoch-boundary reward distribution, triggerable by a single unprivileged user transaction sent between calculation and the target account's distribution partition block. Because all honest validators compute identical feature-set/bank state for the same slot, the panic is not a fork-inducing bug but a full network halt — matching Agave's "epoch-boundary halt" / consensus-halting availability impact category.

### Likelihood Explanation
The attacker needs only to own two of their own stake accounts already delegated to the same vote account with a pending reward for the current epoch, and to time a legitimate `Merge` transaction within the (multi-slot) window between epoch-boundary reward calculation and the specific block where that account's partition is distributed — a window of potentially many slots, giving ample opportunity. This requires no validator/leader control, no mocked paths, and no direct store mutation, only standard stake-program instructions signed by the attacker's own keys. The path is only live while `relax_post_exec_min_balance_check` is not yet active for the cluster/epoch in question (e.g., devnet/testnet, or pre-activation mainnet-beta epochs, and is directly exercised by the existing `test_build_updated_stake_reward(false)` unit test), so likelihood is high wherever that feature gate has not been activated.

### Recommendation
`build_updated_stake_reward` should not assert on a live-vs-cached mismatch caused by legitimate post-calculation stake mutations. Instead, either (a) always take the `adjust_delegation_for_rent`-style reconciliation path (recomputing the effective new delegation from the live account rather than asserting equality with the stale cached value), or (b) detect that the live delegation has diverged from the calculation snapshot and gracefully degrade (e.g., burn/skip the reward similar to `DistributionError` handling for `AccountNotFound`) instead of panicking via `assert_eq!`.

### Proof of Concept
```rust
// program-test integration test sketch (runtime/src/bank/partitioned_epoch_rewards/distribution.rs style)
#[tokio::test]
async fn test_merge_between_calculation_and_distribution_causes_panic() {
    // 1. Set up a bank/cluster where `relax_post_exec_min_balance_check` is inactive.
    // 2. Create stake account A, delegate to vote V, let it fully activate and earn credits.
    // 3. Create stake account B, delegate to vote V as well, fully activate.
    // 4. Advance to the epoch boundary so `begin_partitioned_rewards` calculates rewards for A
    //    (verify A has a non-zero `PartitionedStakeReward` cached, and that A's partition index
    //    has not yet been reached in `store_stake_accounts_in_partition`).
    // 5. Before A's partition block is processed, submit:
    //        stake_instruction::merge(&A, &B, &staker_authority)
    //    signed only by the attacker's own stake authority (no victim accounts involved).
    // 6. Advance to the block that processes A's partition.
    // Expected (buggy) result: `build_updated_stake_reward` panics via
    //    assert_eq!(expected_delegation, new_stake.delegation.stake, ...)
    // Expected (fixed) result: the assertion should never fire; either the reward is
    //    reconciled against the live post-merge delegation, or gracefully skipped/burned.
}
```

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L329-345)
```rust
        let mut epoch_rewards_calculation_cache =
            self.epoch_rewards_calculation_cache.lock().unwrap();
        let rewards_calculation = epoch_rewards_calculation_cache
            .entry(self.parent_hash)
            .or_insert_with(|| {
                Arc::new(self.calculate_rewards_for_partitioning(
                    stake_history,
                    stake_delegations,
                    cached_vote_accounts,
                    rewarded_epoch,
                    reward_epoch_delegated_stakes,
                    reward_calc_tracer,
                    thread_pool,
                    metrics,
                ))
            })
            .clone();
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L249-261)
```rust
        let stake_account = stakes_cache_accounts
            .get(&partitioned_stake_reward.stake_pubkey)
            .ok_or(DistributionError::AccountNotFound)?
            .clone();

        let (mut account, stake_state): (AccountSharedData, StakeStateV2) = stake_account.into();
        let StakeStateV2::Stake(meta, stake, flags) = stake_state else {
            // StakesCache only stores accounts where StakeStateV2::delegation().is_some()
            unreachable!(
                "StakesCache entry {:?} failed StakeStateV2 deserialization",
                partitioned_stake_reward.stake_pubkey
            )
        };
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L284-294)
```rust
        } else {
            let expected_delegation = stake
                .delegation
                .stake
                .saturating_add(partitioned_stake_reward.inflation.stake_reward);
            assert_eq!(
                expected_delegation, new_stake.delegation.stake,
                "stake reward delegation must be consistent with the updated stake account \
                 lamport balance"
            );
        }
```

**File:** runtime/src/bank.rs (L5756-5791)
```rust
    fn update_stakes_cache(
        &self,
        txs: &[impl SVMMessage],
        processing_results: &[TransactionProcessingResult],
    ) {
        debug_assert_eq!(txs.len(), processing_results.len());
        let new_warmup_cooldown_rate_epoch = self.new_warmup_cooldown_rate_epoch();
        let use_fixed_point_stake_math = self.use_fixed_point_stake_math();
        txs.iter()
            .zip(processing_results)
            .filter_map(|(tx, processing_result)| {
                processing_result
                    .processed_transaction()
                    .map(|processed_tx| (tx, processed_tx))
            })
            .filter_map(|(tx, processed_tx)| {
                processed_tx
                    .executed_transaction()
                    .map(|executed_tx| (tx, executed_tx))
            })
            .filter(|(_, executed_tx)| executed_tx.was_successful())
            .flat_map(|(tx, executed_tx)| {
                let num_account_keys = tx.account_keys().len();
                let loaded_tx = &executed_tx.loaded_transaction;
                loaded_tx.accounts.iter().take(num_account_keys)
            })
            .for_each(|(pubkey, account)| {
                // note that this could get timed to: self.rc.accounts.accounts_db.stats.stakes_cache_check_and_store_us,
                //  but this code path is captured separately in ExecuteTimingType::UpdateStakesCacheUs
                self.stakes_cache.check_and_store(
                    pubkey,
                    account,
                    new_warmup_cooldown_rate_epoch,
                    use_fixed_point_stake_math,
                );
            });
```

**File:** runtime/src/stakes.rs (L143-163)
```rust
        } else if stake_program::check_id(owner) {
            match StakeAccount::try_from(create_account_shared_data(account)) {
                Ok(stake_account) => {
                    let mut stakes = self.0.write().unwrap();
                    stakes.upsert_stake_delegation(
                        *pubkey,
                        stake_account,
                        new_rate_activation_epoch,
                        use_fixed_point_stake_math,
                    );
                }
                Err(_) => {
                    let mut stakes = self.0.write().unwrap();
                    stakes.remove_stake_delegation(
                        pubkey,
                        new_rate_activation_epoch,
                        use_fixed_point_stake_math,
                    );
                }
            }
        }
```

**File:** cli/src/stake.rs (L2260-2264)
```rust
    let ixs = stake_instruction::merge(
        stake_account_pubkey,
        source_stake_account_pubkey,
        &stake_authority.pubkey(),
    )
```
