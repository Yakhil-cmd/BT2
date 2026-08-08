### Title
Restart-triggered `recalculate_stake_rewards` recomputes rewards from live `StakesCache` instead of the calculation-block snapshot, causing bank-state divergence for stake accounts modified mid-distribution - ([File: runtime/src/bank/partitioned_epoch_rewards/calculation.rs])

### Summary
`recalculate_stake_rewards`, called only from `initialize_after_snapshot_restore` → `recalculate_partitioned_rewards_if_active` after a snapshot load, recomputes the entire `PartitionedStakeRewards` set from the bank's *current, live* `StakesCache` rather than replaying the exact stake state that existed at the original epoch-boundary calculation block. A node that never restarts instead keeps distributing the values frozen in `EpochRewardStatus::all_stake_rewards` at calculation time. An attacker who mutates their own stake account (e.g. `Withdraw`, `Split`, `Merge`, `Deactivate`) in a block between the calculation block and a validator's restart point can make the restarted node compute a different `stake_reward`/delegation for that account than what non-restarted nodes will apply, producing different resulting bank state for the same slot.

### Finding Description
At the epoch boundary, `begin_partitioned_rewards`/`calculate_rewards_for_partitioning` computes `PartitionedRewardsCalculation` once and caches it as `EpochRewardStatus::Active(EpochRewardPhase::Calculation{ all_stake_rewards, .. })` [1](#0-0) . From then on, every live (non-restarted) bank simply replays these *frozen* values through `distribute_partitioned_epoch_rewards` → `store_stake_accounts_in_partition`, never recomputing stake rewards from current account state [2](#0-1) .

However, when a node restarts from a snapshot taken while rewards are still active, `initialize_after_snapshot_restore` calls `recalculate_partitioned_rewards_if_active`, which calls `recalculate_stake_rewards` [3](#0-2) . This function pulls `stake_delegations` from `self.stakes_cache.stakes()` — the bank's *current* live stake state at the restart slot — via `get_epoch_params_for_recalculation`, and re-runs `calculate_stake_rewards_and_commissions` from scratch [4](#0-3) . There is no mechanism to freeze/snapshot the stake delegation state as it existed at the original calculation block; it simply reads whatever is in the bank's `StakesCache` "now."

If an attacker's own stake account is modified by a normal, unprivileged stake instruction (`Withdraw`, `Split`, `Merge`, `Deactivate`, re-`Delegate`) in a block after the reward-calculation block but before a validator's restart, the delegation amount, `credits_observed`, or activation state visible to `recalculate_stake_rewards` differs from what was baked into the frozen `all_stake_rewards` used by nodes that never restarted. The recalculated `stake_reward` for that pubkey (and the reconstructed `new_stake.delegation.stake` in `build_updated_stake_reward`) will therefore differ between:
- Nodes that stay live and simply replay the calculation-block-frozen `PartitionedStakeReward` for that pubkey, versus
- Nodes that restart and recompute using the mutated, current delegation.

I found no code path (no check in the stake program directories, no gate in `redeem_delegation_rewards`/`calculate_stake_rewards_and_commissions`) that prevents ordinary stake instructions from executing against an account during the calculation→distribution window; the comment in `store_stake_accounts_in_partition` about "further state mutation prevents by stake-program restrictions" only pertains to concurrent same-block account-lock semantics, not a ban on stake instructions across the whole reward interval.

### Impact Explanation
This is a cross-node determinism/consensus divergence: two honest validators processing the identical block sequence, one of which restarted mid-reward-distribution, would apply different lamport amounts / delegation states to the same stake account at the same slot, producing different bank hashes for that slot. This matches Agave's "cross-node state divergence / consensus halt or fork" bounty category, not merely a metrics or cosmetic bug.

### Likelihood Explanation
Preconditions are attacker-controlled and require no special privilege: any staker can submit a `Withdraw`/`Split`/`Merge`/`Deactivate`/`Delegate` instruction on their own stake account. The timing constraint (landing the instruction in the narrow window between the reward-calculation block and an arbitrary validator's restart-from-snapshot point) is opportunistic rather than guaranteed for any specific validator, but validators regularly restart from snapshots (planned maintenance, crash recovery, catch-up from an older snapshot) during the multi-block partitioned-distribution window, especially on networks with many partitions. The attacker does not need to target a specific validator — any validator that restarts during this window while the attacker's transaction has landed will diverge.

### Recommendation
`recalculate_stake_rewards` should not recompute rewards from the bank's live `StakesCache` at the restart slot. Instead, the calculation-block delegation state (or, at minimum, the specific delegation values captured in the original `PartitionedRewardsCalculation`) must be persisted (e.g., serialized as part of the snapshot / `EpochRewardStatus`) and used verbatim on recalculation, so that recalculation is provably identical to what a live bank would have produced regardless of subsequent stake mutations by any account holder.

### Proof of Concept
Integration test plan (Rust, in `runtime/src/bank/partitioned_epoch_rewards/calculation.rs` test module):
1. Build a `RewardBank` with multiple delegations across >1 distribution partition (as in `test_recalculate_partitioned_rewards`).
2. Advance to the epoch boundary so rewards enter `Calculation` phase; capture `expected_stake_rewards` via `calculate_rewards_for_partitioning`.
3. Before advancing to a later distribution block, submit a normal stake `Withdraw`/`Deactivate` instruction that mutates one staker's own stake account's lamports/delegation (simulate via `bank.process_transaction` or direct `store_account` mimicking the instruction's resulting state) for a stake pubkey belonging to a not-yet-distributed partition.
4. Path A ("live node"): advance banks normally through `distribute_partitioned_epoch_rewards`, using the still-frozen `all_stake_rewards`.
5. Path B ("restarted node"): on a bank state at the same block height/slot as Path A, call `bank.recalculate_partitioned_rewards_if_active(...)` and compare its `PartitionedStakeRewards`/`partition_indices` for the affected pubkey to Path A's frozen value.
6. Assert: `recalculated_rewards` for the mutated pubkey differs from `expected_stake_rewards`/Path A's distributed amount — demonstrating that the two code paths produce different `PartitionedStakeReward.inflation.stake_reward` / `stake.delegation.stake` for identical wall-clock state, violating `DETERMINISTIC_STATE`.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L234-296)
```rust
impl Bank {
    /// Begin the process of calculating and distributing rewards.
    /// This process can take multiple slots.
    ///
    /// Returns the total rewards that will be distributed in this epoch (to both validators and
    /// stakers) minus rewards sent to the incinerator.  This is the total amount the capitalization
    /// will increase by after all the rewards have been paid.
    pub(in crate::bank) fn begin_partitioned_rewards(
        &mut self,
        parent_epoch: Epoch,
        parent_slot: Slot,
        parent_block_height: u64,
        rewards_calculation: &PartitionedRewardsCalculation,
        rewards_metrics: &mut RewardsMetrics,
        thread_pool: &ThreadPool,
    ) -> u64 {
        let RewardCommissionLamportAmounts {
            distributed_lamports,
            distributed_to_incinerator_lamports,
            burned_lamports,
        } = self.distribute_reward_commissions(
            parent_epoch,
            rewards_calculation,
            rewards_metrics,
            thread_pool,
        );

        let slot = self.slot();
        let distribution_starting_block_height =
            self.block_height() + REWARD_CALCULATION_NUM_BLOCKS;

        let PartitionedRewardsCalculation {
            stake_rewards,
            point_value,
            ..
        } = rewards_calculation;

        let stake_rewards = Arc::clone(&stake_rewards.stake_rewards);

        let num_partitions = self.get_reward_distribution_num_blocks(&stake_rewards);
        self.set_epoch_reward_status_calculation(distribution_starting_block_height, stake_rewards);

        self.create_epoch_rewards_sysvar(
            distributed_lamports + distributed_to_incinerator_lamports + burned_lamports,
            distribution_starting_block_height,
            num_partitions,
            point_value,
            0, // block_rewards
        );

        datapoint_info!(
            "epoch-rewards-status-update",
            ("start_slot", slot, i64),
            ("calculation_block_height", self.block_height(), i64),
            ("active", 1, i64),
            ("parent_slot", parent_slot, i64),
            ("parent_block_height", parent_block_height, i64),
        );
        distributed_lamports
            + rewards_calculation
                .stake_rewards
                .total_stake_rewards_lamports
    }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L1038-1095)
```rust
    fn recalculate_stake_rewards(
        &self,
        epoch_rewards_sysvar: &EpochRewards,
        thread_pool: &ThreadPool,
    ) -> (Arc<PartitionedStakeRewards>, Vec<Vec<usize>>) {
        assert!(epoch_rewards_sysvar.active);
        // If rewards are active, the rewarded epoch is always the immediately
        // preceding epoch.
        let rewarded_epoch = self.epoch().saturating_sub(1);

        let point_value = PointValue {
            rewards: epoch_rewards_sysvar.total_rewards,
            points: epoch_rewards_sysvar.total_points,
        };

        let stakes = self.stakes_cache.stakes();
        let EpochRewardCalculateParamInfo {
            stake_history,
            stake_delegations,
            cached_vote_accounts,
        } = self.get_epoch_params_for_recalculation(rewarded_epoch, &stakes);
        let ag_epoch_type = AlpenglowEpochType::get(self, rewarded_epoch, || {
            RewardEpochDelegatedStakes::get(self)
        });

        // On recalculation, only the `StakeRewardCalculation::stake_rewards`
        // field is relevant. It is assumed that reward commission accounts have
        // already been calculated and delivered, while
        // `StakeRewardCalculation::total_rewards` only reflects rewards that
        // have not yet been distributed.
        //
        // NOTE: the `RewardCommissionAccounts` will NOT have a correct
        // post_lamport amount if the commission account is NOT the vote account,
        // because the commission account is loaded from the current bank, and
        // not the start of the epoch. We don't have a snapshot of all commission
        // accounts from the start of the epoch. For this reason, the
        // `RewardCommissionAccounts` calculated in this function call should
        // NOT be used ever.
        let (_, StakeRewardCalculation { stake_rewards, .. }) = self
            .calculate_stake_rewards_and_commissions(
                &stake_history,
                stake_delegations,
                cached_vote_accounts,
                rewarded_epoch,
                point_value,
                &ag_epoch_type,
                thread_pool,
                null_tracer(),
                &mut RewardsMetrics::default(), // This is required, but not reporting anything at the moment
            );
        drop(stakes);
        let partition_indices = hash_rewards_into_partitions(
            &stake_rewards,
            &epoch_rewards_sysvar.parent_blockhash,
            epoch_rewards_sysvar.num_partitions as usize,
        );
        (stake_rewards, partition_indices)
    }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L78-149)
```rust
impl Bank {
    /// Process reward distribution for the block if it is inside reward interval.
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

**File:** runtime/src/bank.rs (L6061-6082)
```rust
    /// Compute and apply all activated features, initialize the transaction
    /// processor, and recalculate partitioned rewards if needed
    fn initialize_after_snapshot_restore<F, TP>(&mut self, rewards_thread_pool_builder: F)
    where
        F: FnOnce() -> TP,
        TP: std::borrow::Borrow<ThreadPool>,
    {
        self.transaction_processor =
            TransactionBatchProcessor::new_uninitialized(self.slot, self.epoch);
        if let Some(compute_budget) = &self.compute_budget {
            self.transaction_processor
                .set_execution_cost(compute_budget.to_cost());
        }

        self.compute_and_apply_features_after_snapshot_restore();
        self.stakes_cache.refresh_delegated_stakes(
            self.new_warmup_cooldown_rate_epoch(),
            self.use_fixed_point_stake_math(),
        );

        self.recalculate_partitioned_rewards_if_active(rewards_thread_pool_builder);

```
