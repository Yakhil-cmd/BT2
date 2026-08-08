### Title
Assertion panic in `build_updated_stake_reward` when a stake account's delegation changes between epoch-reward calculation and its deferred partitioned distribution — ([File: runtime/src/bank/partitioned_epoch_rewards/distribution.rs])

### Summary
The external report's bug class is a multi-step/checkpointed operation (`ongoing_soul_tx`) that captures only a partial snapshot of state at the start of a resumable process, and later blindly resumes/finalizes using stale assumptions without re-validating that the state relevant to the operation (the recipient) hasn't changed in the interim. The closest reachable analog in Agave is the **partitioned epoch-rewards distribution** mechanism, which spans multiple blocks: stake rewards are *calculated* once at the epoch boundary and cached in `Bank::epoch_reward_status`, then *distributed* to the corresponding stake accounts over several subsequent blocks/partitions [1](#0-0) . Like `ongoing_soul_tx`, this checkpoint (`StartBlockHeightAndPartitionedRewards`) freezes a precomputed `stake` delegation value per account at calculation time, but the actual "target" (the live stake account) can still be legitimately mutated by its unprivileged owner between calculation and the later distribution block.

### Finding Description
`store_stake_accounts_in_partition` re-fetches the *current* stake delegation from `StakesCache` at distribution time and passes it into `build_updated_stake_reward` alongside the `partitioned_stake_reward` computed earlier at the calculation block [2](#0-1) .

Inside `build_updated_stake_reward`, when the `relax_post_exec_min_balance_check` feature is not active (the legacy/pre-activation code path), the function asserts that the *current* delegation amount plus the *previously calculated* stake reward exactly equals the *precomputed* post-reward delegation from calculation time: [3](#0-2) 

This assumes the stake account's `delegation.stake` at distribution time is identical to what it was at calculation time (plus the reward). However, nothing in the stake program or in `distribute_partitioned_epoch_rewards` prevents the stake account's owner from performing ordinary, unprivileged instructions (e.g., `Split`, `Merge`, `Withdraw`, `Deactivate`) on that same stake account during the multi-block window between reward calculation and its scheduled distribution partition — a window that can last up to 10% of an epoch's slots [4](#0-3) . Any such operation changes `delegation.stake` on-chain, so when that account's distribution partition is finally processed, the `assert_eq!` comparing the freshly-loaded delegation against the stale precomputed value will fail.

This is structurally the same class of bug as the SBT report: the checkpoint (`partitioned_stake_reward`) does not track/re-validate the mutable piece of state (the stake account's current delegation) it will act upon at resume time, and blindly assumes it is unchanged.

### Impact Explanation
An `assert_eq!` failure inside bank processing is a hard `panic!`, which is deterministic across all validators executing the same block (all correct nodes reach the same state and would hit the same assertion). This falls squarely into the accepted "epoch-boundary halt" impact category — the entire cluster would panic while processing the affected distribution partition block during an epoch-boundary rewards period, since epoch-rewards distribution is a Bank-level, non-optional part of block processing, not something that can be filtered out by a single validator.

### Likelihood Explanation
This path is only reachable while `relax_post_exec_min_balance_check` is **not** active; the code comments (`"even if staker's reward is 0..."`, and the explicit branching on `adjust_delegations_for_rent`) indicate this is a legacy code path being phased out by feature activation, and the assert's message ("stake reward delegation must be consistent...") suggests the invariant is expected to hold once the newer feature is enabled. I was not able to confirm from the available index whether `relax_post_exec_min_balance_check` is fully activated on mainnet-beta in this checked-out revision, nor could I confirm whether the stake-program instruction handlers (`programs/stake*/src/*.rs`) were indexed/available to verify there is no cluster-wide restriction preventing stake-state mutation during the active reward-distribution interval. This uncertainty meaningfully lowers confidence in current-day exploitability; the finding should be treated as reachable primarily on networks/feature-set configurations where that feature is not yet active, and needs confirmation of the exact feature-gate status and of the absence of any stake-program-level restriction on splitting/merging/withdrawing a stake account while it holds an unpaid partitioned reward entry.

### Recommendation
- Always exercise the `adjust_delegations_for_rent` path (or an equivalent invariant-tolerant reconciliation) rather than an unconditional `assert_eq!`, regardless of feature-gate status, so that legitimate delegation changes performed by the stake owner between calculation and distribution cannot cause a bank panic.
- Alternatively/additionally, explicitly re-validate or "snapshot-lock" a stake account's delegation once it is selected for a pending partitioned reward (analogous to recording and re-checking the `recipient` in `ongoing_soul_tx`), and gracefully degrade (e.g., skip/burn/recompute) rather than panic when the live account state has diverged from the value captured at calculation time.
- Audit all `assert!`/`assert_eq!`/`unreachable!` calls in the partitioned-rewards distribution pipeline (`runtime/src/bank/partitioned_epoch_rewards/distribution.rs`) for similar "stale state assumed unchanged since checkpoint" invariants, since these all become deterministic-liveness risks once regular user activity is possible during the multi-block distribution window.

### Proof of Concept
Conceptual PoC (not confirmed in a running cluster due to index limitations):
1. Have a stake account with an active delegation earning rewards in epoch N.
2. At the epoch-boundary block of epoch N+1, the bank runs `begin_partitioned_rewards`, computing and caching `partitioned_stake_reward.inflation.stake` for that account into `epoch_reward_status` [5](#0-4) .
3. Before that account's distribution partition is processed (which can be several blocks later), the account owner submits an ordinary `Split` or `Withdraw` stake instruction that changes `delegation.stake` on the live account.
4. When `distribute_partitioned_epoch_rewards` reaches the block/partition containing this account, `store_stake_accounts_in_partition` → `build_updated_stake_reward` loads the now-changed delegation and hits the `assert_eq!` mismatch (on the legacy, non-`adjust_delegations_for_rent` path), panicking bank processing for every validator that processes this block.

I could not verify from the indexed code whether the stake program currently blocks such mutations during an account's pending-reward window, so full end-to-end confirmation would require running this scenario against a live/test validator with the relevant feature flags configured as on current mainnet-beta.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L78-93)
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

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L336-393)
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
