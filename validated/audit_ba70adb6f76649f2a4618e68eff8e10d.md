## Analysis

The CoreDAO bug class is: an unprivileged user can permissionlessly grow an array that a privileged consensus-critical function (`turnRound()`) must fully iterate over in a single pass, with no upper bound, risking exceeding the resource budget (gas limit) and halting the system.

The closest reachable analog in Agave is the epoch-boundary stake-reward calculation path, which iterates over **all** stake delegations in the network in a single, unchunked pass during `process_new_epoch()`, and the number of stake delegations is unbounded and permissionlessly grown by any unprivileged user (just create a stake account, pay rent-exemption + the 1 SOL minimum delegation, and delegate).

Notably, Agave already added exactly this kind of cap for vote accounts (`MAX_ALPENGLOW_VOTE_ACCOUNTS` combined with `VoteAccounts::clone_and_filter_for_vat`), confirming the maintainers recognize unbounded-registration-into-hot-loop as a real risk class needing a cap [1](#0-0) [2](#0-1) . However, no equivalent cap exists for the number of **stake delegations** themselves.

### Title
Unbounded stake-delegation count processed in a single unchunked pass during epoch-boundary reward calculation - (File: runtime/src/bank/partitioned_epoch_rewards/calculation.rs)

### Summary
`Bank::process_new_epoch()` triggers `compute_new_epoch_caches_and_rewards()` → `calculate_rewards()` → `calculate_rewards_for_partitioning()` → `calculate_validator_rewards()`, which calls `calculate_reward_points_partitioned()` and `calculate_stake_rewards_and_commissions()`. Both functions iterate, via a rayon `par_iter()`, over the **entire** `stake_delegations` vector in one synchronous pass at the epoch boundary, before the epoch-boundary block can be considered processed [3](#0-2) [4](#0-3) . Only the subsequent *distribution* (crediting/storing) step is chunked over multiple blocks via `partition_indices`/`num_partitions`; the *calculation* step is not [5](#0-4) .

The number of stake accounts/delegations that must be processed in this single pass is not capped anywhere. Any unprivileged user can create new stake accounts and delegate them, as long as each meets the rent-exempt reserve plus the minimum stake delegation (currently 1 SOL) [6](#0-5) . There is no `CANDIDATE_COUNT_LIMIT`-style cap on the total number of stake delegations analogous to the one already added for vote accounts (`MAX_ALPENGLOW_VOTE_ACCOUNTS`) [7](#0-6) .

### Finding Description
This mirrors the CoreDAO `candidateSet` bug class: an unbounded, permissionlessly-grown collection (`stake_delegations`) is fully iterated by a privileged system function (`process_new_epoch`) that runs once per epoch on every validator, rather than being spread across blocks. While vote accounts received an explicit bound via SIMD-0357 filtering (`clone_and_filter_for_vat`), the stake-delegation collection that both `calculate_reward_points_partitioned` and `calculate_stake_rewards_and_commissions` iterate over has no analogous cap [8](#0-7) .

### Impact Explanation
If the number of stake delegations grows large enough that this single-pass computation cannot complete within the time budget available before the epoch-boundary block must be produced/replayed, this would delay or stall epoch-boundary block production cluster-wide (all validators, not just one, must perform this same computation), which maps to the "epoch-boundary halt" impact category.

### Likelihood Explanation
Likelihood is constrained by the economic cost of creating enough stake accounts (rent-exempt reserve + 1 SOL minimum delegation each) to meaningfully inflate the `stake_delegations` vector, similar to how CoreDAO's `register()` also required a `requiredMargin` deposit yet was still rated Likelihood 2/5. The computation is parallelized via a `ThreadPool` (`rayon`) across delegations, which raises the practical bar further, but there is no hard, protocol-enforced ceiling on the total delegation count — the only throttle is economic cost, not a protocol invariant.

### Recommendation
Introduce a protocol-level cap (or a SIMD-style filtering/truncation step analogous to `clone_and_filter_for_vat`) on the number of stake delegations considered in the single-pass reward-points and reward-calculation loops (`calculate_reward_points_partitioned`, `calculate_stake_rewards_and_commissions`), or chunk the *calculation* phase across multiple blocks the same way the *distribution* phase already is, so that epoch-boundary processing time is bounded independent of total delegation count.

### Proof of Concept
Not independently verifiable from static code review alone — no test in the provided codebase demonstrates a delegation count large enough to exceed epoch-boundary processing time budgets; existing tests use small delegation counts (e.g., 100, 12345) [9](#0-8) , so this remains a structural/scaling concern rather than a demonstrated exploit at current network scale.

### Citations

**File:** vote/src/vote_account.rs (L212-244)
```rust
    pub fn clone_and_filter_for_vat(
        &self,
        max_vote_accounts: usize,
        minimum_vote_account_balance: u64,
    ) -> VoteAccounts {
        assert!(max_vote_accounts > 0, "max_vote_accounts must be > 0");
        let capacity = max_vote_accounts.min(self.vote_accounts.len());
        let mut entries_to_sort: Vec<(&Pubkey, &VoteAccount, u64)> = Vec::with_capacity(capacity);
        for (pubkey, (stake, vote_account)) in self.vote_accounts.iter() {
            let has_bls = vote_account
                .vote_state_view()
                .bls_pubkey_compressed()
                .is_some();
            let has_stake = *stake != 0u64;
            let has_balance = vote_account.lamports() >= minimum_vote_account_balance;

            if !has_bls || !has_stake || !has_balance {
                continue;
            }
            entries_to_sort.push((pubkey, vote_account, *stake));
        }

        let valid_len = entries_to_sort.len();
        if entries_to_sort.len() > max_vote_accounts {
            // Find the cutoff stake using partial sort (more efficient than full sort).
            let (_, cutoff_entry, _) =
                entries_to_sort.select_nth_unstable_by(max_vote_accounts, |a, b| b.2.cmp(&a.2));
            let floor_stake = cutoff_entry.2;

            // Per SIMD 357, we remove all vote accounts with stake smaller or equal to
            // the first truncated one.
            entries_to_sort.retain(|(_, _, stake)| *stake > floor_stake);
        }
```

**File:** runtime/src/bank.rs (L1783-1790)
```rust
        let filtered_distribution_vote_accounts = unfiltered_distribution_vote_accounts
            .clone_and_filter_for_vat(
                MAX_ALPENGLOW_VOTE_ACCOUNTS,
                self.minimum_vote_account_balance_for_vat(),
            );
        if AlpenglowEpochType::is_alpenglow_or_migration_epoch(self, rewarded_epoch) {
            reward_epoch_delegated_stakes.set(self, &filtered_distribution_vote_accounts);
        }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L298-345)
```rust
    // Calculate rewards from previous epoch and distribute reward commissions
    pub(in crate::bank) fn calculate_rewards(
        &self,
        stake_history: &StakeHistory,
        stake_delegations: Vec<(&Pubkey, &StakeAccount<Delegation>)>,
        cached_vote_accounts: CachedVoteAccounts<'_>,
        rewarded_epoch: Epoch,
        reward_epoch_delegated_stakes: RewardEpochDelegatedStakes,
        reward_calc_tracer: Option<impl Fn(&RewardCalculationEvent) + Send + Sync>,
        thread_pool: &ThreadPool,
        metrics: &mut RewardsMetrics,
    ) -> Arc<PartitionedRewardsCalculation> {
        // We hold the lock here for the epoch rewards calculation cache to prevent
        // rewards computation across multiple forks simultaneously. This aligns with
        // how banks are currently created- all banks are created sequentially.
        // As such, this lock does not actually introduce contention because bank
        // creation (and therefore reward calculation) is always done sequentially.
        //
        // However, if we plan to support creating banks in parallel in the future, this logic
        // would need to change to allow rewards computation on multiple forks concurrently.
        // That said, there's still a compelling reason to keep this lock even in a parallel
        // bank creation model: we want to avoid calculating rewards multiple times for the same
        // parent bank hash. This lock ensures that.
        //
        // Creating bank for multiple forks in parallel would also introduce contention for compute resources,
        // potentially slowing down the performance of both forks. This, in turn, could delay
        // vote propagation and consensus for the leading fork—the one most likely to become rooted.
        //
        // Therefore, it seems beneficial to continue processing forks sequentially at epoch
        // boundaries: acquire the lock for the first fork, compute rewards, and let other forks
        // wait until the computation is complete.
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

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L777-820)
```rust
    /// Calculates epoch rewards for stake/commission accounts
    /// Returns commission accounts, stake rewards, and the sum of all stake rewards in lamports
    #[allow(clippy::too_many_arguments)]
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
        let new_warmup_cooldown_rate_epoch = self.new_warmup_cooldown_rate_epoch();
        let feature_snapshot = self.feature_set.snapshot();
        let use_fixed_point_stake_math = feature_snapshot.upgrade_bpf_stake_program_to_v5_1;
        let delay_commission_updates = feature_snapshot.delay_commission_updates;
        let commission_rate_in_basis_points = feature_snapshot.commission_rate_in_basis_points;
        // Name intentionally doesn't match -- "adjust delegations for rent" is
        // part of relaxing post-exec min balance checks.
        let adjust_delegations_for_rent = feature_snapshot.relax_post_exec_min_balance_check;
        let custom_commission_collector = feature_snapshot.custom_commission_collector;
        let block_revenue_sharing = feature_snapshot.block_revenue_sharing;

        let mut measure_redeem_rewards = Measure::start("redeem-rewards");
        // For N stake delegations, where N is >1,000,000, we produce:
        // * N stake rewards,
        // * M reward commission accounts, where M is a number of stake nodes.
        //   Currently, way smaller number than 1,000,000. And we can expect it
        //   to always be significantly smaller than number of delegations.
        //
        // Producing the stake reward with rayon triggers a lot of
        // (re)allocations. To avoid that, we allocate it at the start and
        // pass `stake_rewards.spare_capacity_mut()` as one of iterators.
        let stake_delegations_len = stake_delegations.len();
        let mut stake_rewards = PartitionedStakeRewards::with_capacity(stake_delegations_len);
        let rewards_accumulator: RewardsAccumulator = thread_pool.install(|| {
            stake_delegations
                .par_iter()
                .zip(&mut stake_rewards.spare_capacity_mut()[..stake_delegations_len])
                .with_min_len(500)
                .filter_map(|((stake_pubkey, stake_account), reward_ref)| {
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L942-1002)
```rust
    fn calculate_reward_points_partitioned<'a>(
        &self,
        stake_history: &StakeHistory,
        stake_delegations: &Vec<(&'a Pubkey, &'a StakeAccount<Delegation>)>,
        cached_vote_accounts: &CachedVoteAccounts<'_>,
        epoch_inflation_rewards: u64,
        ag_epoch_type: &AlpenglowEpochType,
        thread_pool: &ThreadPool,
        metrics: &RewardsMetrics,
    ) -> Option<PointValue> {
        let CachedVoteAccounts {
            distribution_epoch_vote_accounts,
            ..
        } = cached_vote_accounts;

        let solana_vote_program: Pubkey = solana_vote_program::id();
        let new_warmup_cooldown_rate_epoch = self.new_warmup_cooldown_rate_epoch();
        match ag_epoch_type {
            AlpenglowEpochType::Alpenglow { .. } => {
                // In alpenglow, we do not need to compute `PointValue::points` as the final
                // rewards are simply the total credits stored in the vote account.  We just need
                // to return a `Some` value with valid rewards.
                return Some(PointValue {
                    rewards: epoch_inflation_rewards,
                    points: 0,
                });
            }
            AlpenglowEpochType::Tower => {
                // For tower we need to compute the valid `PointValue::points`.
            }
            AlpenglowEpochType::MigrationEpoch { .. } => {
                // For the migrating epoch, we need to compute the tower portion of `PointValue::points`.
            }
        }

        let use_fixed_point_stake_math = self.use_fixed_point_stake_math();
        let (points, measure_us) = measure_us!(thread_pool.install(|| {
            stake_delegations
                .par_iter()
                .map(|(_stake_pubkey, stake_account)| {
                    let vote_pubkey = stake_account.delegation().voter_pubkey;

                    let Some(vote_account) = distribution_epoch_vote_accounts.get(&vote_pubkey)
                    else {
                        return 0;
                    };
                    if vote_account.owner() != &solana_vote_program {
                        return 0;
                    }

                    calculate_points_for_tower(
                        stake_account.stake_state(),
                        DelegatedVoteState::from(vote_account.vote_state_view()),
                        stake_history,
                        new_warmup_cooldown_rate_epoch,
                        use_fixed_point_stake_math,
                    )
                    .unwrap_or(0)
                })
                .sum::<u128>()
        }));
```

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L403-428)
```rust
    /// # stake accounts to store in one block during partitioned reward interval
    pub(super) fn partitioned_rewards_stake_account_stores_per_block(&self) -> u64 {
        self.partitioned_rewards_stake_account_stores_per_block
    }

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

**File:** runtime/src/stake_utils.rs (L15-27)
```rust
/// The minimum stake amount that can be delegated, in lamports.
/// When this feature is added, it will be accompanied by an upgrade to the BPF Stake Program.
/// NOTE: This is also used to calculate the minimum balance of a delegated stake account,
/// which is the rent exempt reserve _plus_ the minimum stake delegation.
#[inline(always)]
pub fn get_minimum_delegation(upgrade_bpf_stake_program_to_v5_is_active: bool) -> u64 {
    if upgrade_bpf_stake_program_to_v5_is_active {
        const MINIMUM_DELEGATION_SOL: u64 = 1;
        MINIMUM_DELEGATION_SOL * LAMPORTS_PER_SOL
    } else {
        1
    }
}
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L643-666)
```rust
    /// Test partitioned credits and reward history updates of epoch rewards do cover all the rewards
    /// slice.
    #[test]
    fn test_epoch_credit_rewards_and_history_update() {
        let (mut genesis_config, _mint_keypair) =
            create_genesis_config(1_000_000 * LAMPORTS_PER_SOL);
        genesis_config.epoch_schedule = EpochSchedule::custom(432000, 432000, false);
        let bank = Bank::new_for_tests(&genesis_config);

        // setup the expected number of stake rewards
        let expected_num = 12345;

        let mut stake_rewards = (0..expected_num)
            .map(|_| PartitionedStakeReward::new_random())
            .collect::<Vec<_>>();
        let expected_block_rewards = stake_rewards
            .iter()
            .map(|reward| reward.block_reward)
            .sum::<u64>();
        populate_starting_stake_accounts_from_stake_rewards(
            &bank,
            &bank.rent_collector.rent,
            &stake_rewards,
        );
```
