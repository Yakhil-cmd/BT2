### Title
`build_updated_stake_reward()` panics on `assert_eq!` mismatch when a stake account's delegation changes between reward-calculation and reward-distribution blocks - (File: `runtime/src/bank/partitioned_epoch_rewards/distribution.rs`)

### Summary
Partitioned epoch rewards are computed once, at the epoch boundary, from a snapshot of the `StakesCache`, but they are *paid out* over many subsequent blocks (up to 10% of the epoch's slots) in `distribute_partitioned_epoch_rewards()` / `store_stake_accounts_in_partition()`. When a payout for a given stake account is finally applied, `build_updated_stake_reward()` re-reads the *current* stake account from the cache and asserts that its `delegation.stake` plus the previously-computed reward exactly equals the reward-calculation-time `delegation.stake`. This is directly analogous to the reported `GammaVault.rebalancePosition()` bug: a value computed and cached at one point in time is later used to satisfy a hard invariant/assertion, and if the underlying stake state is mutated in the interim, the invariant is violated and the code panics rather than gracefully recomputing or erroring.

### Finding Description
`store_stake_accounts_in_partition()` calls `build_updated_stake_reward()` once per stake account in the current distribution partition, for every block during the reward-distribution window: [1](#0-0) 

Inside `build_updated_stake_reward`, when `adjust_delegations_for_rent` is not active (i.e., the `relax_post_exec_min_balance_check` feature is off), the code enforces: [2](#0-1) 

`stake.delegation.stake` here is read fresh from the `StakesCache` at distribution time (line 249, `stakes_cache_accounts.get(...)`), while `new_stake.delegation.stake` (`partitioned_stake_reward.inflation.stake`) was computed earlier, at the epoch-boundary calculation block, from a point-in-time snapshot of the same account. Between the calculation block and the distribution block for a given account's partition (which can be many slots later, per `get_reward_distribution_num_blocks`), the stake delegation can legitimately change — for example, through the stake account owner issuing `Split`, `Merge`, `Deactivate`, or `DelegateStake` instructions, which mutate `Stake.delegation.stake` and get reflected into `StakesCache` via `update_stakes_cache` on every processed transaction: [3](#0-2) [4](#0-3) 

If `stake.delegation.stake + stake_reward != new_stake.delegation.stake` at distribution time, the `assert_eq!` fires and panics the validator process handling that block — the equivalent of the reported bug's reverted/"stuck" transaction, except here it is a hard panic in bank-processing code rather than a recoverable instruction error.

### Impact Explanation
An `assert_eq!` panic inside block-processing/consensus-critical bank code (`build_updated_stake_reward`, invoked from `distribute_partitioned_epoch_rewards`) is not a per-transaction failure; it aborts the entire validator process while processing a normal, deterministic epoch-boundary block. Because reward distribution and the underlying stake-account state transitions are deterministic across the cluster, any validator that reaches the same block height with the same account state will hit the identical assertion, producing a correlated, cluster-wide crash exactly at an epoch boundary — this matches the accepted "epoch-boundary halt" impact category.

### Likelihood Explanation
Likelihood is Medium: the trigger condition requires (a) a stake account being scheduled for a stake reward in the epoch-boundary calculation, and (b) that same account's stake delegation changing (e.g. via `Split`/`Merge`/`Deactivate`/`DelegateStake`) before its specific partition is processed during the (multi-block) distribution window, and (c) the `relax_post_exec_min_balance_check` feature being inactive so the `adjust_delegations_for_rent` branch is not taken. Any unprivileged stake-account owner can perform ordinary stake operations on their own account during this window; whether the stake program itself blocks such operations while `EpochRewards` is "active" could not be verified in this repository, because the current stake-program instruction processor appears to have been migrated to Core BPF (outside `programs/stake` in this codebase) and its instruction-level checks were not found in the indexed code. This is a material unknown that a Devin session with full repo/BPF-program access should confirm before treating this as fully proven.

### Recommendation
Do not use a hard `assert_eq!`/panic to enforce consistency between the calculation-time and distribution-time delegation values. Instead:
- Recompute or reconcile the delegation deterministically from the current on-chain state (similar to the `adjust_delegations_for_rent` branch), or
- Return a `DistributionError` (as is already done elsewhere in this function, e.g. `DistributionError::ArithmeticOverflow`, `DistributionError::UnableToSetState`) instead of panicking when a mismatch is detected, allowing the reward to be safely burned/logged like other failure paths in `store_stake_accounts_in_partition`, or
- If not already enforced by the stake program, explicitly disallow delegation-mutating stake instructions while the `EpochRewards` sysvar is active for accounts pending payout, eliminating the race entirely.

### Proof of Concept
Conceptual reproduction (not fully verified against the on-chain stake-program instruction gating, which is outside this repo's indexed BPF program code):
1. Reach an epoch boundary so that `begin_partitioned_rewards` computes and caches `PartitionedStakeReward` entries per stake account, based on `StakesCache` state at that instant: [5](#0-4) .
2. Choose a stake account whose reward is scheduled for a later partition (multiple blocks into the distribution window, see `get_reward_distribution_num_blocks`): [6](#0-5) .
3. Before that partition's block height is reached, submit an ordinary `Split` or `Merge` stake-program transaction from the stake authority that changes `Stake.delegation.stake` on that account; this transaction updates `StakesCache` immediately via `update_stakes_cache`: [7](#0-6) .
4. When the validator reaches the block that distributes that account's partition, `build_updated_stake_reward` reads the now-mutated delegation and compares it against the pre-computed `expected_delegation`, triggering the `assert_eq!` panic: [2](#0-1) .

### Citations

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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L336-392)
```rust
    fn store_stake_accounts_in_partition(
        &self,
        partition_rewards: &StartBlockHeightAndPartitionedRewards,
        partition_index: u64,
    ) -> DistributionResults {
        let feature_snapshot = self.feature_set.snapshot();
        // Name intentionally doesn't match -- "adjust delegations for rent" is
        // part of relaxing post-exec min balance checks.
        let adjust_delegations_for_rent = feature_snapshot.relax_post_exec_min_balance_check;
        let use_fixed_point_stake_math = feature_snapshot.upgrade_bpf_stake_program_to_v5_1;

        let mut stake_reward_lamports_minted = 0;
        let mut stake_reward_lamports_burned = 0;
        let mut block_reward_lamports_distributed = 0;
        let mut block_reward_lamports_burned = 0;
        let indices = partition_rewards
            .partition_indices
            .get(partition_index as usize)
            .unwrap_or_else(|| {
                panic!(
                    "partition index out of bound: {partition_index} >= {}",
                    partition_rewards.partition_indices.len()
                )
            });
        let mut updated_stake_rewards = Vec::with_capacity(indices.len());
        let stakes_cache = self.stakes_cache.stakes();
        let stakes_cache_accounts = stakes_cache.stake_delegations();
        let stake_history = stakes_cache.history();
        let new_warmup_cooldown_rate_epoch = self.new_warmup_cooldown_rate_epoch();
        let rent = &self.rent_collector.rent;
        for index in indices {
            let partitioned_stake_reward = partition_rewards
                .all_stake_rewards
                .get(*index)
                .unwrap_or_else(|| {
                    panic!(
                        "partition reward out of bound: {index} >= {}",
                        partition_rewards.all_stake_rewards.total_len()
                    )
                })
                .as_ref()
                .unwrap_or_else(|| {
                    panic!("partition reward {index} is empty");
                });
            let stake_pubkey = partitioned_stake_reward.stake_pubkey;
            let stake_reward_amount = partitioned_stake_reward.inflation.stake_reward;
            let block_reward_amount = partitioned_stake_reward.block_reward;

            match Self::build_updated_stake_reward(
                self.epoch,
                stake_history,
                new_warmup_cooldown_rate_epoch,
                stakes_cache_accounts,
                partitioned_stake_reward,
                rent,
                adjust_delegations_for_rent,
                use_fixed_point_stake_math,
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

**File:** runtime/src/stakes.rs (L620-660)
```rust
    fn upsert_stake_delegation(
        &mut self,
        stake_pubkey: Pubkey,
        stake_account: StakeAccount,
        new_rate_activation_epoch: Option<Epoch>,
        use_fixed_point_stake_math: bool,
    ) {
        debug_assert_ne!(stake_account.lamports(), 0u64);
        let delegation = stake_account.delegation();
        let voter_pubkey = delegation.voter_pubkey;
        let stake = delegation_effective_stake(
            delegation,
            self.epoch,
            &self.stake_history,
            new_rate_activation_epoch,
            use_fixed_point_stake_math,
        );
        match self.stake_delegations.insert(stake_pubkey, stake_account) {
            None => {
                self.add_delegated_stake(voter_pubkey, stake);
                self.vote_accounts.add_stake(&voter_pubkey, stake);
            }
            Some(old_stake_account) => {
                let old_delegation = old_stake_account.delegation();
                let old_voter_pubkey = old_delegation.voter_pubkey;
                let old_stake = delegation_effective_stake(
                    old_delegation,
                    self.epoch,
                    &self.stake_history,
                    new_rate_activation_epoch,
                    use_fixed_point_stake_math,
                );
                if voter_pubkey != old_voter_pubkey || stake != old_stake {
                    self.sub_delegated_stake(&old_voter_pubkey, old_stake);
                    self.add_delegated_stake(voter_pubkey, stake);
                    self.vote_accounts.sub_stake(&old_voter_pubkey, old_stake);
                    self.vote_accounts.add_stake(&voter_pubkey, stake);
                }
            }
        }
    }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L241-296)
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

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L408-428)
```rust
    /// Calculate the number of blocks required to distribute rewards to all stake accounts.
    pub(super) fn get_reward_distribution_num_blocks(
        &self,
        rewards: &PartitionedStakeRewards,
    ) -> u64 {
        let total_stake_accounts = rewards.num_rewards();
        if self.epoch_schedule.warmup && self.epoch < self.first_normal_epoch() {
            1
        } else {
            const MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH: u64 = 10;
            let num_chunks = total_stake_accounts
                .div_ceil(self.partitioned_rewards_stake_account_stores_per_block() as usize)
                as u64;

            // Limit the reward credit interval to 10% of the total number of slots in a epoch
            num_chunks.clamp(
                1,
                (self.epoch_schedule.slots_per_epoch / MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH).max(1),
            )
        }
    }
```
