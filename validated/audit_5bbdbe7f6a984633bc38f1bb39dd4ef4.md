### Title
Hard panic in reward distribution when a stake account's delegation is mutated between reward calculation and reward payout - ([File: runtime/src/bank/partitioned_epoch_rewards/distribution.rs])

### Summary
This is the same bug class as the Brava report: a "before" value is captured for accounting purposes, an intervening state-changing operation is allowed to run against the same account, and the "after" comparison then fails hard instead of degrading gracefully. In agave, the intervening state change is a stake-program instruction (e.g. `Merge`/`Split`/`Deactivate`) executed on a stake account whose reward has already been *calculated* but not yet *distributed* (partitioned rewards can span many blocks). When the distribution code later re-reads the account and asserts the delegation matches what was pre-computed, a mismatch triggers a hard `assert_eq!` panic rather than a recoverable error.

### Finding Description
Reward payout is split into two phases: `calculate_stake_rewards_and_commissions` computes a `PartitionedStakeReward` for every delegation at the epoch boundary [1](#0-0) , and then, over the following blocks, `build_updated_stake_reward` re-reads the *current* stake account from `stakes_cache_accounts` and merges in the pre-computed reward [2](#0-1) .

When the `relax_post_exec_min_balance_check` feature (`adjust_delegations_for_rent`) is not active, the code takes the following path:
```
let expected_delegation = stake.delegation.stake.saturating_add(partitioned_stake_reward.inflation.stake_reward);
assert_eq!(
    expected_delegation, new_stake.delegation.stake,
    "stake reward delegation must be consistent with the updated stake account lamport balance"
);
``` [3](#0-2) 

Here `stake` is the *live* delegation read from the cache at distribution time, while `new_stake` is the delegation that was computed during the earlier calculation phase. The code's own comment concedes the assumption this relies on:
```
/// Because stake accounts are checked in calculation, and further state
/// mutation prevents by stake-program restrictions, there should never be
/// rewards burned.
``` [4](#0-3) 

This is exactly the Brava pattern: a "before" balance/delegation is captured, some other operation is permitted to change the account in the interim, and the code that reconciles "before" vs. "after" was written under the assumption that no such interim mutation is possible. I was not able to locate, in this index, an explicit guard in the stake-program instruction handlers that rejects `Merge`/`Split`/`Deactivate`/`DelegateStake` while a stake account has a pending, undistributed partitioned reward — the restriction the comment refers to is not visible from the code paths I could search (this may be enforced elsewhere in the stake program, e.g. via `MergeKind`/state-consistency checks not surfaced by my searches; the index has size limits and this cannot be fully ruled out from Ask alone).

If such an interim stake-program mutation to `delegation.stake` is in fact possible during the distribution window, `assert_eq!` fails and panics `store_stake_accounts_in_partition`/`build_updated_stake_reward`, which runs identically on every validator processing the deterministic reward-distribution block — this is a consensus-critical, unprivileged-user-reachable path (any user can submit ordinary stake instructions), not a validator/operator-only action.

### Impact Explanation
A panic here occurs inside `distribute_epoch_rewards_in_partition`, which is invoked once per block during the epoch-reward-distribution window from `distribute_partitioned_epoch_rewards` [5](#0-4) . Because this logic executes deterministically for every validator replaying/producing blocks at the epoch boundary, a triggered panic would crash the entire fleet simultaneously — an epoch-boundary halt, which is explicitly listed as an acceptable-impact category.

### Likelihood Explanation
Likelihood cannot be confirmed as high without verifying whether the stake program actually blocks state-mutating stake instructions while a stake account has an outstanding partitioned reward. The code comment strongly implies this restriction is *relied upon* but I could not find the enforcing check in the instruction-handler code within the indexed content, so this should be treated as a plausible-but-unverified gap rather than a confirmed exploit. If no such restriction exists (or if it has an edge case, e.g. around `Merge`, `Redelegate`, or feature-gate transitions changing `adjust_delegations_for_rent` mid-epoch), the bug is trivially and repeatedly triggerable by any user.

### Recommendation
- Confirm whether stake-program instruction processors actually check `EpochRewards::active`/pending-reward status before allowing `Merge`, `Split`, `Deactivate`, `Redelegate`, or `DelegateStake` on an account with an uncredited partitioned reward.
- Regardless, remove the hard `assert_eq!` in `build_updated_stake_reward` (`runtime/src/bank/partitioned_epoch_rewards/distribution.rs` lines 284-294) and replace it with the same graceful reconciliation used in the `adjust_delegations_for_rent` branch, or a `DistributionError` that safely burns/re-derives the reward instead of panicking, so that any unexpected interim mutation degrades safely instead of halting consensus.

### Proof of Concept
Not constructed — reproducing this would require confirming, in a live/test validator, that a stake-program instruction (e.g. `Merge`) can successfully execute against a stake pubkey between the reward-calculation block and its assigned reward-distribution block, thereby changing `delegation.stake` and violating the assert. This requires runtime/test-validator access beyond what is available in Ask-only code search, and is flagged above as an area of uncertainty.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L780-791)
```rust
    fn calculate_stake_rewards_and_commissions<'a>(
        &self,
        stake_history: &StakeHistory,
        stake_delegations: Vec<(&'a Pubkey, &'a StakeAccount<Delegation>)>,
        cached_vote_accounts: CachedVoteAccounts<'_>,
        rewarded_epoch: Epoch,
        point_value: PointValue,
        ag_epoch_type: &AlpenglowEpochType,
        thread_pool: &ThreadPool,
        reward_calc_tracer: Option<impl RewardCalcTracer>,
        metrics: &mut RewardsMetrics,
    ) -> (RewardCommissions, StakeRewardCalculation) {
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L80-150)
```rust
    pub(in crate::bank) fn distribute_partitioned_epoch_rewards(&mut self) {
        let EpochRewardStatus::Active(status) = &self.epoch_reward_status else {
            return;
        };

        let distribution_starting_block_height = match &status {
            EpochRewardPhase::Calculation(status) => status.distribution_starting_block_height,
            EpochRewardPhase::Distribution(status) => status.distribution_starting_block_height,
        };

        let height = self.block_height();
        if height < distribution_starting_block_height {
            return;
        }

        if let EpochRewardPhase::Calculation(status) = &status {
            // epoch rewards have not been partitioned yet, so partition them now
            // This should happen only once immediately on the first rewards distribution block, after reward calculation block.
            let epoch_rewards_sysvar = self.get_epoch_rewards_sysvar();
            let (partition_indices, partition_us) = measure_us!({
                epoch_rewards_hasher::hash_rewards_into_partitions(
                    &status.all_stake_rewards,
                    &epoch_rewards_sysvar.parent_blockhash,
                    epoch_rewards_sysvar.num_partitions as usize,
                )
            });

            // update epoch reward status to distribution phase
            self.set_epoch_reward_status_distribution(
                distribution_starting_block_height,
                Arc::clone(&status.all_stake_rewards),
                partition_indices,
            );

            datapoint_info!(
                "epoch-rewards-status-update",
                ("slot", self.slot(), i64),
                ("block_height", height, i64),
                ("partition_us", partition_us, i64),
                (
                    "distribution_starting_block_height",
                    distribution_starting_block_height,
                    i64
                ),
            );
        }

        let EpochRewardStatus::Active(EpochRewardPhase::Distribution(partition_rewards)) =
            &self.epoch_reward_status
        else {
            // We should never get here.
            unreachable!(
                "epoch rewards status is not in distribution phase, but we are trying to \
                 distribute rewards"
            );
        };

        let distribution_end_exclusive =
            distribution_starting_block_height + partition_rewards.partition_indices.len() as u64;

        assert!(
            self.epoch_schedule.get_slots_in_epoch(self.epoch)
                > partition_rewards.partition_indices.len() as u64
        );

        if height >= distribution_starting_block_height && height < distribution_end_exclusive {
            let partition_index = height - distribution_starting_block_height;

            self.distribute_epoch_rewards_in_partition(partition_rewards, partition_index);
        }

```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L239-254)
```rust
    fn build_updated_stake_reward(
        distribution_epoch: u64,
        stake_history: &StakeHistory,
        new_warmup_cooldown_rate_epoch: Option<Epoch>,
        stakes_cache_accounts: &imbl::HashMap<Pubkey, StakeAccount<Delegation>>,
        partitioned_stake_reward: &PartitionedStakeReward,
        rent: &Rent,
        adjust_delegations_for_rent: bool,
        use_fixed_point_stake_math: bool,
    ) -> Result<StakeReward, DistributionError> {
        let stake_account = stakes_cache_accounts
            .get(&partitioned_stake_reward.stake_pubkey)
            .ok_or(DistributionError::AccountNotFound)?
            .clone();

        let (mut account, stake_state): (AccountSharedData, StakeStateV2) = stake_account.into();
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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L330-332)
```rust
    /// Because stake accounts are checked in calculation, and further state
    /// mutation prevents by stake-program restrictions, there should never be
    /// rewards burned.
```
