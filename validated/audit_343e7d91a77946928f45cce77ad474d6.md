### Title
Recalculated block-reward distribution can over-count `pending_delegator_rewards` after partial distribution already occurred - (File: `runtime/src/bank/partitioned_epoch_rewards/calculation.rs`)

### Summary
This finding is analogous to the PoolTogether bug class: a reward is computed as a fraction of a "pool" total that is read *before* accounting for amounts already consumed from that same pool by a prior action, causing the pool to be effectively double counted and reward recipients to receive more than intended.

### Finding Description
`calculate_block_reward` computes each stake delegation's share of a vote account's block-revenue pool (`pending_delegator_rewards`) as `pending_delegator_rewards * stake / total_active_stake`, where `total_active_stake` is a frozen snapshot taken via `RewardEpochDelegatedStakes` at the end of the rewarded epoch [1](#0-0) .

`pending_delegator_rewards` is a single, on-chain value stored in the vote account (incremented externally via `DepositDelegatorRewards`, i.e., `add_pending_delegator_rewards`) [2](#0-1) . Nowhere in the reward calculation or distribution path is this field decremented as individual stake accounts are paid their share; the same full `pending_delegator_rewards` value is read again on every recomputation.

Crucially, the code explicitly documents that when rewards are **recalculated** (via `recalculate_partitioned_rewards_if_active` → `recalculate_stake_rewards` → `calculate_stake_rewards_and_commissions` → `calculate_block_reward`, which happens when a new bank fork must recompute pending distribution for an epoch whose earlier partitions have already been paid out), the `stake` value fed into the block-reward formula can already reflect stake that was credited by a previously-distributed partition, so `stake > total_active_stake` can occur: [3](#0-2) 

The recalculation path is invoked with the *unmodified* `pending_delegator_rewards` numerator (no accounting for the block-reward lamports already minted to earlier partitions in `store_stake_accounts_in_partition`/`build_updated_stake_reward` via `partitioned_stake_reward.block_reward`) [4](#0-3) , while the denominator/`stake` numerator used for the still-undistributed accounts can already be inflated. This is structurally the same defect as the PoolTogether report: a fixed "pool" total (`pending_delegator_rewards`, analogous to `reserveForOpenDraw`) is used to compute a share for a recipient set without subtracting the portion of that pool already paid out to a different recipient set, so the pool gets counted more than once across the full distribution.

### Impact Explanation
If the aggregate of per-partition block-reward shares computed this way exceeds the vote account's actual `pending_delegator_rewards` balance, later `store_stake_accounts_in_partition` calls would credit stake accounts with `block_reward` lamports that were never actually backed by a corresponding debit from the vote account's `pending_delegator_rewards`/lamport balance — this is a form of over-minting/misattributed lamports in a reward-distribution path, which the rules classify as in-scope impact.

### Likelihood Explanation
The code's own comment ("it's possible to have `stake > total_active_stake`... individual rewards look greater than the pending rewards... harmless in practice, but we clamp it just to be safe") shows the authors are aware the per-stake reward can be computed as larger than intended during recalculation, and only clamp the *per-account* value to `pending_delegator_rewards`, not the *aggregate* across all recalculated (remaining) partitions. This requires the specific, but real, condition of an active `EpochRewardStatus::Distribution` state being recalculated mid-epoch (fork switch while epoch rewards are still being paid out block-by-block) combined with non-zero `pending_delegator_rewards`/`block_revenue_sharing` enabled — a state reachable in normal validator operation without any privileged actor, since anyone can trigger `DepositDelegatorRewards` and fork switches during the distribution window are routine.

### Recommendation
When recalculating stake rewards for partitions not yet distributed (`recalculate_stake_rewards`), the `pending_delegator_rewards` value used as the numerator in `calculate_block_reward` should be reduced by the amount already distributed to previously-processed partitions in the current epoch's reward cycle (tracked via the epoch rewards sysvar, similar to how `distributed_rewards`/`update_epoch_rewards_sysvar` already tracks inflation rewards distributed) rather than reusing the full original snapshot value alongside a `stake` value that may already include prior distributions.

### Proof of Concept
Not independently reproduced in a live cluster/test harness within this analysis; the concern is derived directly from the documented, acknowledged edge case in `calculate_block_reward` combined with the confirmed absence of any code path that reduces `pending_delegator_rewards` as reward partitions are distributed [5](#0-4) [6](#0-5) . Confirming actual over-distribution (versus a merely theoretical/"harmless" outcome as the inline comment asserts) would require constructing a test that: (1) enables `block_revenue_sharing`/`custom_commission_collector`, (2) distributes several partitions of an epoch's rewards, (3) forces a fork switch that triggers `recalculate_partitioned_rewards_if_active` for the remaining partitions, and (4) sums the total `block_reward` lamports credited across all partitions versus the vote account's original `pending_delegator_rewards` balance — this was not performed here due to tool/iteration limits.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L173-211)
```rust
/// Calculates block reward for a stake account based on SIMD-0123
fn calculate_block_reward(
    rewarded_epoch: Epoch,
    delegation: &Delegation,
    stake_history: &StakeHistory,
    distribution_epoch_vote_accounts: &VoteAccounts,
    ag_epoch_type: &AlpenglowEpochType,
    new_warmup_cooldown_rate_epoch: Option<Epoch>,
    use_fixed_point_stake_math: bool,
) -> u64 {
    let vote_pubkey = delegation.voter_pubkey;
    let Some(vote_account) = distribution_epoch_vote_accounts.get(&vote_pubkey) else {
        debug!("could not find vote account {vote_pubkey} in cache");
        return 0;
    };
    let vote_state = vote_account.vote_state_view();
    let pending_delegator_rewards = vote_state.pending_delegator_rewards();
    // NOTE: during recalculation, `distribution_epoch_vote_accounts` already
    // includes updated stake activation values from after the new epoch
    // calculation, so we need to use `RewardEpochDelegatedStakes` for the exact
    // values at the end of the reward epoch.
    let (AlpenglowEpochType::Alpenglow {
        reward_epoch_delegated_stakes,
        ..
    }
    | AlpenglowEpochType::MigrationEpoch {
        reward_epoch_delegated_stakes,
        ..
    }) = ag_epoch_type
    else {
        debug!("Alpenglow must be enabled for block reward calculation");
        return 0;
    };
    let total_active_stake = reward_epoch_delegated_stakes
        .delegated_stakes
        .get(&vote_pubkey)
        .copied()
        .unwrap_or(0);
    if total_active_stake == 0 {
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L221-230)
```rust
        // During recalculation, if stake account has already received rewards,
        // it's possible to have `stake > total_active_stake`. If
        // `pending_delegator_rewards` is a huge number, we could potentially
        // overflow a `u64`. We can also have individual rewards look greater
        // than the pending rewards. This is harmless in practice, but we
        // clamp it just to be safe
        (pending_delegator_rewards as u128 * stake as u128 / total_active_stake as u128)
            .try_into()
            .unwrap_or(u64::MAX)
            .min(pending_delegator_rewards)
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L1011-1095)
```rust
    /// If rewards are still active, recalculates partitioned stake rewards and
    /// updates Bank::epoch_reward_status. This method assumes that reward
    /// commissions have already been calculated and delivered, and *only*
    /// recalculates stake rewards
    pub(in crate::bank) fn recalculate_partitioned_rewards_if_active<F, TP>(
        &mut self,
        thread_pool_builder: F,
    ) where
        F: FnOnce() -> TP,
        TP: std::borrow::Borrow<ThreadPool>,
    {
        let epoch_rewards_sysvar = self.get_epoch_rewards_sysvar();
        if epoch_rewards_sysvar.active {
            let thread_pool = thread_pool_builder();
            let (stake_rewards, partition_indices) =
                self.recalculate_stake_rewards(&epoch_rewards_sysvar, thread_pool.borrow());
            self.set_epoch_reward_status_distribution(
                epoch_rewards_sysvar.distribution_starting_block_height,
                stake_rewards,
                partition_indices,
            );
        }
    }

    /// Returns a vector of partitioned stake rewards. StakeRewards are
    /// recalculated from an active EpochRewards sysvar, vote accounts from
    /// EpochStakes, and stake accounts from StakesCache.
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

**File:** programs/vote/src/vote_state/handler.rs (L196-209)
```rust
    pub(crate) fn add_pending_delegator_rewards(
        &mut self,
        amount: u64,
    ) -> Result<(), InstructionError> {
        match &mut self.target_state {
            TargetVoteState::V4(v4) => {
                v4.pending_delegator_rewards = v4
                    .pending_delegator_rewards
                    .checked_add(amount)
                    .ok_or(InstructionError::ArithmeticOverflow)?;
                Ok(())
            }
        }
    }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L262-267)
```rust
        account
            .checked_add_lamports(partitioned_stake_reward.inflation.stake_reward)
            .map_err(|_| DistributionError::ArithmeticOverflow)?;
        account
            .checked_add_lamports(partitioned_stake_reward.block_reward)
            .map_err(|_| DistributionError::ArithmeticOverflow)?;
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L336-423)
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
            ) {
                Ok(stake_reward) => {
                    stake_reward_lamports_minted += stake_reward_amount;
                    block_reward_lamports_distributed += block_reward_amount;
                    updated_stake_rewards.push(stake_reward);
                }
                Err(err) => {
                    error!(
                        "bank::distribution::store_stake_accounts_in_partition() failed for \
                         {stake_pubkey}, {stake_reward_amount} lamports burned: {err:?}"
                    );
                    stake_reward_lamports_burned += stake_reward_amount;
                    block_reward_lamports_burned += block_reward_amount;
                }
            }
        }
        drop(stakes_cache);
        self.store_accounts(
            (self.slot(), &updated_stake_rewards[..]),
            // Reuse the rewards calculation thread pool to parallelize
            // loading the previous versions of the stake accounts.
            Some(crate::bank::rewards_calculation_thread_pool()),
        );
        DistributionResults {
            stake_reward_lamports_minted,
            stake_reward_lamports_burned,
            block_reward_lamports_distributed,
            block_reward_lamports_burned,
            updated_stake_rewards,
        }
    }
```
