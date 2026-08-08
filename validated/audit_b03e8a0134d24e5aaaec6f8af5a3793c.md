### Title
`Bank::recalculate_stake_rewards` recomputes per-account inflation reward from live, attacker-mutable `StakesCache` state instead of the delegation snapshot frozen at epoch-boundary calculation, causing cross-node divergence for stake accounts split/merged/withdrawn before a snapshot-triggered recalculation - ([File: runtime/src/bank/partitioned_epoch_rewards/calculation.rs])

### Summary
`Bank::recalculate_stake_rewards` (called from `Bank::recalculate_partitioned_rewards_if_active`, in turn invoked by `Bank::initialize_after_snapshot_restore` and `Bank::new_for_block_tests`) rebuilds the pending stake-reward list by reading `self.stakes_cache.stakes()` at recalculation time [1](#0-0) . Unlike the vote-account total-stake denominator, which was explicitly frozen via `RewardEpochDelegatedStakes` to fix a related bug [2](#0-1) , the per-stake-account numerator (`stake.delegation.stake`, `stake.credits_observed`) used in `calculate_stake_points_and_credits`/`tower_epoch_credits_iter` is taken from whatever the account currently looks like in `StakesCache`, not from a snapshot of the account as it existed at the original epoch-boundary reward calculation [3](#0-2) . A validator that never restarts keeps distributing the immutable `all_stake_rewards` computed once at the epoch boundary [4](#0-3) , while a validator that restarts from a snapshot taken after the attacker split/merged/withdrew their own stake will recompute a different `stake_reward` for the same `stake_pubkey`/epoch.

### Finding Description
The reward flow is:
1. At the epoch boundary, `calculate_rewards_for_partitioning` computes `all_stake_rewards` once from the then-current `StakesCache`, and this list is cached into `EpochRewardStatus::Active(EpochRewardPhase::Calculation/Distribution)` [5](#0-4) .
2. For the remainder of the epoch's distribution window, a bank that stays alive and simply advances through `Bank::new_from_parent` never recomputes this list — it only carries forward the previously cached `all_stake_rewards` and pays out one partition per block via `distribute_epoch_rewards_in_partition` [6](#0-5) .
3. If a bank is instead rebuilt from a snapshot mid-distribution, `initialize_after_snapshot_restore` calls `recalculate_partitioned_rewards_if_active` → `recalculate_stake_rewards`, which pulls `stake_delegations` fresh from `self.stakes_cache.stakes()` at the moment of restart and re-runs the exact same reward-computation pipeline (`calculate_stake_rewards_and_commissions` → `redeem_delegation_rewards` → `calculate_stake_points_and_credits`) [7](#0-6) .
4. `calculate_stake_points_and_credits` (Tower) and `calculate_alpenglow_points` (Alpenglow) both compute `stake_amount` from `stake.delegation.stake` read out of whatever `Stake` struct is passed in — i.e. the *current* delegation, not the one that existed when the epoch-boundary calculation ran [8](#0-7) [9](#0-8) .
5. An unprivileged attacker who owns a delegated, active stake account can freely issue `split`, `merge`, or `withdraw` stake instructions against their own account at any point after the epoch boundary and before their partition is distributed — no code path found in this repo gates these stake instructions on `EpochRewards` sysvar being active (no `epoch_rewards_active`/similar guard was found in the stake program). Any such instruction changes `stake.delegation.stake` (and potentially `credits_observed`) for the affected `stake_pubkey`.
6. If a validator restarts from a snapshot taken after that mutating transaction lands but before that stake_pubkey's partition is distributed, `recalculate_stake_rewards` will compute a `stake_reward` for that pubkey based on the mutated delegation, differing from the frozen value already cached (and used) by validators that never recalculated. The fix applied in `test_recalculate_alpenglow_rewards_after_partial_distribution_uses_original_denominator` only froze the vote-account-level total-stake denominator via `RewardEpochDelegatedStakes`; it explicitly does not address the per-stake numerator, which remains re-derived from the live account state on every recalculation [10](#0-9) .

This is not a mocked/store-mutation path; the attacker uses only ordinary, publicly available stake instructions on an account they own, and the divergence is triggered purely by the natural, permitted restart-and-recalculate code path already present in production (`initialize_after_snapshot_restore`).

### Impact Explanation
Two honest validators — one that stayed continuously live through the reward distribution window and one that restarted from a snapshot taken after the attacker's stake mutation but before the affected partition was distributed — will compute and pay out different `stake_reward` lamport amounts for the same `stake_pubkey` and epoch. Since stake-reward payouts directly mutate account lamports and feed into the bank hash, this produces a cross-node state/bank-hash divergence for otherwise-honest validators, matching the bounty category of "misattributed or duplicated rewards" / "cross-node state divergence," and can escalate to a consensus halt if enough validators disagree (some paid amount A, others amount B for the same account).

### Likelihood Explanation
This requires: (a) an active `EpochRewards` distribution window (occurs every epoch), (b) the attacker owning any active, delegated stake account with a pending (not-yet-distributed) reward, (c) the attacker issuing an ordinary `split`, `merge`, or `withdraw` instruction on their own stake account during that window, and (d) at least one validator taking a snapshot after the mutation and restarting/loading from it before that pubkey's partition is processed. Snapshotting and restart-from-snapshot are routine, unprivileged-attacker-independent operational events (new validators joining, node restarts, ledger-tool operations, `new_for_block_tests`-style bootstrap paths), so precondition (d) is not attacker-controlled but is a common and repeatable occurrence in the network, making the divergence realistically triggerable by a single unprivileged stake-mutation transaction timed within the multi-block distribution window (whose length is `num_partitions`, generally spanning many blocks).

### Recommendation
Freeze the entire per-stake input used for reward recalculation (not just the vote-account total-stake denominator) at the original epoch-boundary calculation time. Concretely, persist (or re-derive deterministically from bank-hash-covered, immutable state) the `Stake`/`Delegation`/`credits_observed` values as they were when `calculate_rewards_for_partitioning` first ran, and have `recalculate_stake_rewards` operate over that frozen snapshot rather than `self.stakes_cache.stakes()` at recalculation time. Alternatively, disallow `split`/`merge`/`withdraw` on stake accounts with a still-pending, undistributed reward for the previous epoch (mirroring how the vote-account denominator freeze was implemented via `RewardEpochDelegatedStakes`).

### Proof of Concept
Extend `test_recalculate_alpenglow_rewards_after_partial_distribution_uses_original_denominator`-style test in `runtime/src/bank/partitioned_epoch_rewards/calculation.rs`:
1. Build a `RewardBank` with an attacker-owned stake account with a pending (unpaid) reward for `rewarded_epoch`, per `create_reward_bank_with_specific_stakes`.
2. Advance to the epoch boundary; capture `EpochRewardStatus::Active(Calculation(status))`, record `status.all_stake_rewards`'s entry for the attacker's `stake_pubkey` (`expected_reward`).
3. **Path A (live node):** without touching the stake account, advance blocks via `Bank::new_from_parent` until the attacker's partition is reached; capture the actually-paid `stake_reward` from `distribute_epoch_rewards_in_partition`/resulting lamport delta. Assert it equals `expected_reward`.
4. **Path B (restart node):** on a clone/fork of the same pre-boundary bank, apply a `stake::split` (or `merge`/`withdraw`) instruction on the attacker's stake account after the epoch boundary but before their partition's distribution block, then simulate snapshot restore (`bank.feature_set = Arc::new(FeatureSet::default()); bank.initialize_after_snapshot_restore(...)`), and call `bank.recalculate_stake_rewards(&epoch_rewards_sysvar, &thread_pool)` directly (as done in existing tests).
5. Assert `recalculated_stake_rewards` for the same `stake_pubkey` differs from `expected_reward` (the Path A value), demonstrating that Path A and Path B produce bit-different `stake_reward` for the identical `stake_pubkey`/epoch — violating the required "identical on all honest nodes" invariant, analogous to `compare_stake_rewards` assertions used elsewhere in this file (e.g. `test_recalculate_stake_rewards`, lines 2417-2537).

### Citations

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

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L2677-2798)
```rust
    #[test]
    fn test_recalculate_alpenglow_rewards_after_partial_distribution_uses_original_denominator() {
        let stake_lamports = 2_000_000_000;
        let validator_keypairs = vec![genesis_utils::ValidatorVoteKeypairs::new_rand()];
        let GenesisConfigInfo {
            mut genesis_config, ..
        } = genesis_utils::create_genesis_config_with_alpenglow_vote_accounts(
            1_000_000_000 * LAMPORTS_PER_SOL,
            &validator_keypairs,
            vec![stake_lamports],
        );
        genesis_config.epoch_schedule = EpochSchedule::new(SLOTS_PER_EPOCH);
        let features_to_deactivate = crate::slot_params::slot_time_feature_ids().to_vec();
        deactivate_features(&mut genesis_config, &features_to_deactivate);

        let mut accounts_db_config: AccountsDbConfig = ACCOUNTS_DB_CONFIG_FOR_TESTING;
        accounts_db_config.partitioned_epoch_rewards_config =
            PartitionedEpochRewardsConfig::new_for_test(1);
        let bank = Bank::new_from_genesis(
            &genesis_config,
            Arc::new(RuntimeConfig::default()),
            Vec::new(),
            None,
            accounts_db_config,
            None,
            None,
            Arc::default(),
            None,
            None,
        );

        let vote_pubkey = validator_keypairs[0].vote_keypair.pubkey();
        let vote_account = bank.get_account(&vote_pubkey).unwrap();
        let extra_stake_pubkey = Pubkey::new_unique();
        let extra_stake_account = stake_utils::create_stake_account(
            &extra_stake_pubkey,
            &vote_pubkey,
            &vote_account,
            &bank.rent_collector.rent,
            stake_lamports,
        );
        bank.store_account_and_update_capitalization(&extra_stake_pubkey, &extra_stake_account);

        let (bank, bank_forks) = bank.wrap_with_bank_forks_for_tests();
        let bank = Bank::new_from_parent_with_bank_forks(
            bank_forks.as_ref(),
            bank,
            SlotLeader::default(),
            SLOTS_PER_EPOCH,
        );
        assert_eq!(bank.epoch(), 1);

        let mut vote_account = bank.get_account(&vote_pubkey).unwrap();
        let VoteStateVersions::V4(mut vote_state) = vote_account
            .deserialize_data::<VoteStateVersions>()
            .unwrap()
        else {
            panic!("unexpected vote state version");
        };
        let last_credits = vote_state
            .epoch_credits
            .last()
            .map(|(_epoch, final_credits, _initial_credits)| *final_credits)
            .unwrap_or_default();
        vote_state
            .epoch_credits
            .push((bank.epoch(), last_credits + 1_000_000, last_credits));
        vote_account
            .serialize_data(&VoteStateVersions::V4(vote_state))
            .unwrap();
        bank.store_account(&vote_pubkey, &vote_account);

        let thread_pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();
        let mut bank = Bank::new_from_parent(
            bank,
            SlotLeader::default(),
            SLOTS_PER_EPOCH.saturating_mul(2),
        );
        assert_eq!(bank.epoch(), 2);

        let EpochRewardStatus::Active(EpochRewardPhase::Calculation(calculation_status)) =
            bank.epoch_reward_status.clone()
        else {
            panic!("{:?} not active calculation", bank.epoch_reward_status);
        };
        let original_stake_rewards = calculation_status.all_stake_rewards;
        let original_rewards = original_stake_rewards
            .enumerated_rewards_iter()
            .collect::<Vec<_>>();
        assert_eq!(original_rewards.len(), 2);
        let (paid_index, paid_reward) = original_rewards[0];
        let (unpaid_index, unpaid_reward) = original_rewards[1];
        assert!(paid_reward.inflation.stake_reward > 0);
        assert!(unpaid_reward.inflation.stake_reward > 0);

        // Force exactly one stake reward to be distributed before simulating
        // snapshot restore. That write updates StakesCache with a larger
        // delegation for the same vote account.
        bank.set_epoch_reward_status_distribution(
            bank.block_height(),
            Arc::clone(&original_stake_rewards),
            vec![vec![paid_index], vec![unpaid_index]],
        );
        bank.distribute_partitioned_epoch_rewards();

        let epoch_rewards_sysvar = bank.get_epoch_rewards_sysvar();
        assert!(epoch_rewards_sysvar.active);
        let (recalculated_stake_rewards, _partition_indices) =
            bank.recalculate_stake_rewards(&epoch_rewards_sysvar, &thread_pool);
        let recalculated_unpaid_reward = recalculated_stake_rewards
            .enumerated_rewards_iter()
            .find_map(|(_index, reward)| {
                (reward.stake_pubkey == unpaid_reward.stake_pubkey).then_some(reward)
            })
            .expect("unpaid stake reward must still be pending after recalculation");

        assert_eq!(
            unpaid_reward.inflation.stake_reward, recalculated_unpaid_reward.inflation.stake_reward,
            "recalculation after partial distribution must use the same AG delegated stake \
             denominator as the original epoch-boundary calculation"
        );
    }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L2939-2992)
```rust
    #[test]
    fn test_initialize_after_snapshot_restore() {
        let expected_num_stake_rewards = 4;
        let num_rewards_per_block = 2;
        // Distribute 4 rewards over 2 blocks
        let stakes = vec![
            100_000_000,   // valid delegation
            2_000_000_000, // valid delegation
            3_000_000_000, // valid delegation
            4_000_000_000, // valid delegation
        ];
        let (RewardBank { bank, .. }, bank_forks) = create_reward_bank_with_specific_stakes(
            stakes,
            num_rewards_per_block,
            SLOTS_PER_EPOCH - 1,
        );

        // Advance to next epoch boundary (bank_forks kept in scope so parent has fork_graph)
        let new_slot = bank.slot() + 1;
        let mut bank = Bank::new_from_parent(bank, SlotLeader::default(), new_slot);

        let EpochRewardStatus::Active(EpochRewardPhase::Calculation(calculation_status)) =
            bank.epoch_reward_status.clone()
        else {
            panic!("{:?} not active calculation", bank.epoch_reward_status);
        };

        // Reset feature set to default, to simulate snapshot restore
        bank.feature_set = Arc::new(FeatureSet::default());

        // Run post snapshot restore initialization which should first apply
        // active features and then recalculate rewards
        let thread_pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();
        bank.initialize_after_snapshot_restore(|| &thread_pool);

        let EpochRewardStatus::Active(EpochRewardPhase::Distribution(distribution_status)) =
            bank.epoch_reward_status.clone()
        else {
            panic!("{:?} not active distribution", bank.epoch_reward_status);
        };

        assert_eq!(
            calculation_status.all_stake_rewards,
            distribution_status.all_stake_rewards
        );
        assert_eq!(
            calculation_status.distribution_starting_block_height,
            distribution_status.distribution_starting_block_height
        );
        assert_eq!(
            calculation_status.all_stake_rewards.num_rewards(),
            expected_num_stake_rewards
        );
        let _ = &bank_forks; // Keep in scope so parent banks retain fork_graph
```

**File:** runtime/src/inflation_rewards/points.rs (L187-222)
```rust
fn tower_epoch_credits_iter(
    stake: &Stake,
    epoch_credits_iter: impl Iterator<Item = (Epoch, u64, u64)>,
    stake_history: &StakeHistory,
    inflation_point_calc_tracer: Option<impl Fn(&InflationPointCalculationEvent)>,
    new_rate_activation_epoch: Option<Epoch>,
    use_fixed_point_stake_math: bool,
) -> (u128, u64, bool) {
    let mut points = 0;
    let credits_in_stake = stake.credits_observed;
    let mut new_credits_observed = credits_in_stake;
    let mut saw_marker = false;

    for entry in epoch_credits_iter {
        if entry == AG_MIGRATION_EPOCH_CREDIT {
            saw_marker = true;
            break;
        }
        let (epoch, final_epoch_credits, initial_epoch_credits) = entry;
        let earned_credits = calc_earned_credits(
            stake,
            final_epoch_credits,
            initial_epoch_credits,
            &mut new_credits_observed,
        );
        let stake_amount = u128::from(delegation_effective_stake(
            &stake.delegation,
            epoch,
            stake_history,
            new_rate_activation_epoch,
            use_fixed_point_stake_math,
        ));

        // finally calculate points for this epoch
        let earned_points = stake_amount * earned_credits;
        points += earned_points;
```

**File:** runtime/src/inflation_rewards/points.rs (L243-301)
```rust
fn calculate_alpenglow_points(
    stake: &Stake,
    reward_epoch_credits: Option<(Epoch, u64, u64)>,
    stake_history: &StakeHistory,
    inflation_point_calc_tracer: Option<impl Fn(&InflationPointCalculationEvent)>,
    new_rate_activation_epoch: Option<Epoch>,
    use_fixed_point_stake_math: bool,
    reward_epoch_delegated_stakes: &RewardEpochDelegatedStakes,
) -> Result<(u128, u64), CalculatedStakePoints> {
    let Some((epoch, final_epoch_credits, initial_epoch_credits)) = reward_epoch_credits else {
        return Ok((0, stake.credits_observed));
    };
    if epoch != reward_epoch_delegated_stakes.epoch {
        // In this case, the vote account did not record any credits in this epoch
        // The latest entry is from a prior epoch - thus the delegation gets 0 rewards
        return Ok((0, stake.credits_observed));
    }

    let (earned_credits, new_credits_observed) = {
        let mut new_credits_observed = stake.credits_observed;
        let earned_credits = calc_earned_credits(
            stake,
            final_epoch_credits,
            initial_epoch_credits,
            &mut new_credits_observed,
        );
        (earned_credits, new_credits_observed)
    };

    let stake_amount = u128::from(delegation_effective_stake(
        &stake.delegation,
        epoch,
        stake_history,
        new_rate_activation_epoch,
        use_fixed_point_stake_math,
    ));

    let earned_points = if earned_credits == 0 || stake_amount == 0 {
        0
    } else {
        let Some(total_stake) = reward_epoch_delegated_stakes
            .delegated_stakes
            .get(&stake.delegation.voter_pubkey)
            .copied()
            .filter(|stake| *stake != 0)
        else {
            record_error(format!(
                "AG delegated stake denominator for vote_pubkey={} in epoch={} failed",
                stake.delegation.voter_pubkey, reward_epoch_delegated_stakes.epoch
            ));
            return Err(CalculatedStakePoints {
                tower_points: 0,
                ag_points: 0,
                new_credits_observed,
                force_credits_update_with_skipped_reward: true,
            });
        };
        earned_credits * stake_amount / total_stake as u128
    };
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
