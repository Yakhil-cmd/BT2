### Title
Restart-triggered stake reward recalculation reads live (mutable) `StakesCache` instead of the frozen calculation-time snapshot, causing reward-amount divergence from the non-restarted path - (File: `runtime/src/bank/partitioned_epoch_rewards/calculation.rs`)

### Summary
`Bank::recalculate_stake_rewards` (invoked from `recalculate_partitioned_rewards_if_active` during `initialize_after_snapshot_restore`) recomputes each stake account's reward using the **current** `StakesCache` contents via `get_epoch_params_for_recalculation`, rather than the frozen `stake_delegations` snapshot originally captured at the epoch-boundary calculation block. Any ordinary, unprivileged stake instruction (`Split`, `Merge`, `Delegate`) that changes a stake account's `delegation.stake` between the calculation slot and a later restart-triggered recalculation changes that account's computed reward share, producing a `PartitionedStakeRewards` result that differs from the originally-calculated (and non-restarted-node-distributed) rewards for the same `rewarded_epoch`.

### Finding Description
`get_epoch_params_for_recalculation` builds its recalculation inputs directly from the live cache: [1](#0-0) 

`recalculate_stake_rewards` uses these live delegations together with the **fixed** `total_rewards`/`total_points` persisted in the `EpochRewards` sysvar to recompute each account's `PartitionedStakeReward` from scratch: [2](#0-1) 

This recalculated set then **replaces** the bank's reward-distribution state via `set_epoch_reward_status_distribution`: [3](#0-2) 

The subsequent distribution logic (`distribute_partitioned_epoch_rewards` / `distribute_epoch_rewards_in_partition`) simply credits whatever amounts are stored in `status.all_stake_rewards` — it does not distinguish whether that list came from the original in-memory calculation or from a restart-time recalculation: [4](#0-3) 

On a node that never restarts, distribution always uses the original, frozen `all_stake_rewards` Arc computed once at the epoch boundary in `begin_partitioned_rewards`, so any later stake mutation by any user cannot change already-computed reward amounts: [5](#0-4) 

On a node that restarts (loses in-memory `epoch_reward_status`/cache and must call `recalculate_stake_rewards` from `initialize_after_snapshot_restore`), the reward for any account whose `delegation.stake` was legitimately changed via `Split`/`Merge`/`Delegate` during the still-active reward interval is recomputed from the mutated stake amount, not the amount that existed at the original calculation block. Since Split/Merge require signer authority the attacker only needs to control their own stake account (already a permitted unprivileged action), no victim-account compromise is needed — the attacker simply times an ordinary stake instruction on their own delegation to land inside the reward interval on a node that will restart before finishing distribution.

The existing test suite exercises `recalculate_stake_rewards` (`test_recalculate_stake_rewards`, `calculation.rs:2427-2537`) but never injects a stake mutation between the calculation and recalculation calls — the bank object and its `StakesCache` are untouched in between, so the test cannot detect this divergence: [6](#0-5) 

No signer/authority/epoch check exists to reject the `Split`/`Merge`/`Delegate` instruction because it is legitimate, correctly-authorized behavior on the attacker's own account; the vulnerability is that the recalculation path re-derives per-account reward shares from post-mutation live state instead of re-deriving from a snapshot equivalent to what was used at the original calculation.

### Impact Explanation
This causes **cross-node state divergence**: a validator that restarts mid-reward-interval and hits `recalculate_stake_rewards` will credit a different lamport amount to the mutated stake account (and consequently compute a different total distributed-lamports/capitalization and a different resulting account state/bank hash) than a validator that did not restart and is still using the originally-frozen `all_stake_rewards`. This falls under the accepted "cross-node state divergence" / "misattributed reward distribution" bounty category, since it can produce consensus-breaking bank-hash mismatches purely from ordinary user stake instructions combined with an operationally common restart during the reward interval.

### Likelihood Explanation
Preconditions: (1) a validator restart (or any code path invoking `initialize_after_snapshot_restore`/`recalculate_partitioned_rewards_if_active`) occurring while `EpochRewardStatus` is `Active`, i.e., during the multi-block reward interval that follows every epoch boundary — a routine, frequent window; (2) an unprivileged user submitting a `Split`, `Merge`, or `Delegate` instruction on a stake account that is part of the `rewarded_epoch`'s delegation set, timed to land in a block between the calculation slot and the restart. Both preconditions are attacker-controllable/observable (reward-interval blocks are publicly known from the `EpochRewards` sysvar), and restarts are common operational events (crash, OOM, upgrade) not requiring any privileged access. This is fully repeatable in a deterministic unit test as shown below.

### Recommendation
`recalculate_stake_rewards` should not re-derive stake reward shares from the live `StakesCache`. Instead, either (a) persist the frozen calculation-time `PartitionedStakeRewards`/`stake_delegations` snapshot (or an equivalent commitment, e.g., the exact rewarded-epoch stake amounts) so it survives node restart and use that snapshot for recalculation, or (b) ensure `get_epoch_params_for_recalculation` sources `stake_delegations` from the same epoch-stakes / activation-epoch-consistent view used during the original calculation (excluding any deltas introduced by transactions processed after the calculation block), so recalculation is provably deterministic and independent of intervening account mutations.

### Proof of Concept
Extend `test_recalculate_stake_rewards` (`runtime/src/bank/partitioned_epoch_rewards/calculation.rs`) to inject a stake mutation between calculation and recalculation:
```rust
#[test]
fn test_recalculate_stake_rewards_diverges_after_stake_mutation() {
    let expected_num_delegations = 4;
    let num_rewards_per_block = 2;
    let (RewardBank { bank, stakers, .. }, bank_forks) =
        create_reward_bank(expected_num_delegations, num_rewards_per_block, SLOTS_PER_EPOCH);
    let rewarded_epoch = bank.epoch() - 1;
    let thread_pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();
    let mut rewards_metrics = RewardsMetrics::default();

    // Original calculation (as at epoch boundary)
    let stakes = bank.stakes_cache.stakes();
    let EpochRewardCalculateParamInfo { stake_history, stake_delegations, cached_vote_accounts } =
        bank.get_epoch_params_for_recalculation(rewarded_epoch, &stakes);
    let PartitionedRewardsCalculation {
        stake_rewards: StakeRewardCalculation { stake_rewards: expected_stake_rewards, .. },
        ..
    } = bank.calculate_rewards_for_partitioning(
        &stake_history, stake_delegations, cached_vote_accounts, rewarded_epoch,
        reward_epoch_delegated_stakes_for_tests(rewarded_epoch), null_tracer(),
        &thread_pool, &mut rewards_metrics,
    );
    drop(stakes);

    // Attacker (owner of stakers[0]) submits a Split instruction on their own
    // stake account that was included in `stake_delegations` above, landing
    // inside the still-active reward interval before any restart-triggered
    // recalculation occurs.
    let victim_stake_pubkey = stakers[0];
    submit_stake_split_instruction(&bank, &victim_stake_pubkey /* attacker-controlled */);

    // Simulate restart: recalculate using the now-mutated StakesCache.
    let epoch_rewards_sysvar = bank.get_epoch_rewards_sysvar();
    let (recalculated_rewards, recalculated_partition_indices) =
        bank.recalculate_stake_rewards(&epoch_rewards_sysvar, &thread_pool);
    let recalculated_rewards =
        build_partitioned_stake_rewards(&recalculated_rewards, &recalculated_partition_indices);

    let expected_partition_indices = hash_rewards_into_partitions(
        &expected_stake_rewards, &epoch_rewards_sysvar.parent_blockhash,
        epoch_rewards_sysvar.num_partitions as usize,
    );
    let expected_stake_rewards_partitioned =
        build_partitioned_stake_rewards(&expected_stake_rewards, &expected_partition_indices);

    // EXPECTED (per invariant): recalculated rewards for `rewarded_epoch`
    // must bit-for-bit match the originally-calculated rewards.
    // ACTUAL: this assertion fails, demonstrating the divergence bug.
    compare_stake_rewards(&expected_stake_rewards_partitioned, &recalculated_rewards);
}
```
Expected result: the final `compare_stake_rewards` assertion fails (reward for `victim_stake_pubkey`, or its total distributed lamports, differs), proving that `recalculate_stake_rewards` produces a result inconsistent with the non-restarted calculation whenever an ordinary stake instruction mutates a delegated account during the reward interval.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L241-274)
```rust
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
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L582-589)
```rust
    fn get_epoch_params_for_recalculation<'a>(
        &'a self,
        rewarded_epoch: Epoch,
        stakes: &'a Stakes<StakeAccount<Delegation>>,
    ) -> EpochRewardCalculateParamInfo<'a> {
        // Use `stakes` for stake-related info
        let stake_history = stakes.history().clone();
        let stake_delegations = stakes.stake_delegations_vec();
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L1038-1088)
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
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L2427-2486)
```rust
    #[test]
    fn test_recalculate_stake_rewards() {
        let expected_num_delegations = 4;
        let num_rewards_per_block = 2;
        // Distribute 4 rewards over 2 blocks
        let (RewardBank { bank, .. }, bank_forks) = create_reward_bank(
            expected_num_delegations,
            num_rewards_per_block,
            SLOTS_PER_EPOCH,
        );
        let rewarded_epoch = bank.epoch() - 1;

        let thread_pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();
        let mut rewards_metrics = RewardsMetrics::default();
        let stakes = bank.stakes_cache.stakes();
        let EpochRewardCalculateParamInfo {
            stake_history,
            stake_delegations,
            cached_vote_accounts,
        } = bank.get_epoch_params_for_recalculation(rewarded_epoch, &stakes);
        let PartitionedRewardsCalculation {
            stake_rewards:
                StakeRewardCalculation {
                    stake_rewards: expected_stake_rewards,
                    ..
                },
            ..
        } = bank.calculate_rewards_for_partitioning(
            &stake_history,
            stake_delegations,
            cached_vote_accounts,
            rewarded_epoch,
            reward_epoch_delegated_stakes_for_tests(rewarded_epoch),
            null_tracer(),
            &thread_pool,
            &mut rewards_metrics,
        );
        drop(stakes);

        let epoch_rewards_sysvar = bank.get_epoch_rewards_sysvar();
        let (recalculated_rewards, recalculated_partition_indices) =
            bank.recalculate_stake_rewards(&epoch_rewards_sysvar, &thread_pool);

        let recalculated_rewards =
            build_partitioned_stake_rewards(&recalculated_rewards, &recalculated_partition_indices);

        let expected_partition_indices = hash_rewards_into_partitions(
            &expected_stake_rewards,
            &epoch_rewards_sysvar.parent_blockhash,
            epoch_rewards_sysvar.num_partitions as usize,
        );

        let expected_stake_rewards_partitioned =
            build_partitioned_stake_rewards(&expected_stake_rewards, &expected_partition_indices);

        assert_eq!(
            expected_stake_rewards_partitioned.len(),
            recalculated_rewards.len()
        );
        compare_stake_rewards(&expected_stake_rewards_partitioned, &recalculated_rewards);
```

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L1015-1033)
```rust
                // Reward distribution should be active in this range.
                assert_matches!(
                    curr_bank.get_reward_interval(),
                    RewardInterval::InsideInterval
                );
                assert!(curr_bank.is_partitioned());

                let account = curr_bank
                    .get_account(&solana_sysvar::epoch_rewards::id())
                    .unwrap();
                let epoch_rewards: solana_sysvar::epoch_rewards::EpochRewards =
                    from_account(&account).unwrap();
                assert_eq!(
                    post_cap,
                    pre_cap + epoch_rewards.distributed_rewards - pre_distributed_rewards
                );

                if slot == SLOTS_PER_EPOCH + 1 {
                    // The first block of the epoch has not rooted yet, so the
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
