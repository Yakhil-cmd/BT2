### Title
Unbounded, Non-Partitioned Reward-Calculation Scan Over All Stake Delegations at Epoch Boundary Can Stall Cluster Progress - ([File: runtime/src/bank/partitioned_epoch_rewards/calculation.rs])

### Summary
Solana's "partitioned epoch rewards" feature was built specifically to avoid a class of bug identical to the reported `Revolver._checkSolePlayer()` issue: an unbounded, single-shot scan over all active participants performed inside one atomic state transition. However, only the *distribution* (storing rewards into stake accounts) half of the epoch-reward pipeline is chunked across multiple blocks. The *calculation* half — the O(n) scan over every stake delegation on the network to compute points and rewards — still runs synchronously and in full inside the single epoch-boundary block, on every validator, as part of unconditional bank/slot transition logic (not a discretionary transaction that can simply fail/be skipped).

### Finding Description
`Bank::process_new_epoch` calls `compute_new_epoch_caches_and_rewards`, which calls `Bank::calculate_rewards`, which calls `calculate_rewards_for_partitioning` -> `calculate_validator_rewards` -> `calculate_reward_points_partitioned` and `calculate_stake_rewards_and_commissions`. [1](#0-0) 

`calculate_reward_points_partitioned` iterates (in parallel, but still `O(n)` work) over the *entire* `stake_delegations` vector — every stake account on the cluster with a delegation — to compute reward points: [2](#0-1) 

`calculate_stake_rewards_and_commissions` similarly does a full `par_iter` pass over `stake_delegations` (its own comment acknowledges N can be "greater than 1,000,000") to redeem rewards for every delegation: [3](#0-2) 

Unlike vote accounts, which are explicitly capped/filtered via `clone_and_filter_for_vat(MAX_ALPENGLOW_VOTE_ACCOUNTS, ...)` before being used in reward math: [4](#0-3) 

...there is no equivalent cap on `stake_delegations`. The `PartitionedStakeRewards` output of this calculation is only *afterward* split into chunks for distribution over multiple subsequent blocks via `begin_partitioned_rewards` / `get_reward_distribution_num_blocks`: [5](#0-4) 

But the calculation itself — the part whose cost scales with the total number of stake delegations — happens once, entirely within the first block of the epoch, exactly the "callback"-equivalent moment (`Bank::new_from_parent` at an epoch boundary) that every validator must process synchronously and deterministically before any user transactions in that slot can even be considered. This is structurally the same bug class as `Revolver`'s `_checkSolePlayer()`: an unbounded per-participant scan is embedded inside a single, mandatory state-transition step rather than being chunked like the rest of the pipeline.

### Impact Explanation
If the number of active stake delegations on the network grows large enough (each delegation currently costs only `get_minimum_delegation()` = 1 SOL plus the stake account's rent-exempt reserve, and is fully recoverable by deactivating/withdrawing after use): [6](#0-5) 

...the calculation phase's per-epoch cost grows without bound and without any partitioning/backpressure mechanism, unlike the (VAT-capped) vote-account path. Because this computation is mandatory, synchronous, and identical across every validator processing the epoch-boundary bank, an attacker who inflates the delegation count sufficiently can push this single block's processing time past acceptable bounds for the whole cluster simultaneously — producing a cluster-wide slot-processing delay/stall precisely at epoch boundaries, which is one of the explicitly in-scope impact categories ("epoch-boundary halt").

### Likelihood Explanation
Likelihood is limited by cost: at the current 1 SOL minimum delegation, materially slowing this scan would require a very large amount of locked capital (proportional to the number of delegations an attacker wants to add). This makes the attack expensive but not impossible for well-resourced actors, and the underlying design gap (calculation is *not* partitioned like distribution, and has no cap analogous to `MAX_ALPENGLOW_VOTE_ACCOUNTS`) is a genuine architectural asymmetry rather than a theoretical-only concern.

### Recommendation
Apply the same mitigation pattern already used for vote accounts (`MAX_ALPENGLOW_VOTE_ACCOUNTS` / VAT filtering) to the reward-points and reward-redemption scans over `stake_delegations`, or split `calculate_reward_points_partitioned` / `calculate_stake_rewards_and_commissions` into an incremental, multi-block computation analogous to the existing partitioned distribution phase, so that no single block's processing cost is proportional to an unbounded, attacker-influenced count of stake delegations.

### Proof of Concept
Not applicable in the traditional sense (no test harness access); the vulnerable pattern is demonstrated directly by the code path `process_new_epoch` → `compute_new_epoch_caches_and_rewards` → `calculate_rewards` → `calculate_rewards_for_partitioning` → `calculate_reward_points_partitioned`/`calculate_stake_rewards_and_commissions`, all executing unconditionally and fully within one block at every epoch boundary over the complete `stake_delegations` set, with the existing test `test_epoch_boundary` confirming this calculation happens exactly once, synchronously, at the first block of each epoch: [7](#0-6)

### Citations

**File:** runtime/src/bank.rs (L1783-1792)
```rust
        let filtered_distribution_vote_accounts = unfiltered_distribution_vote_accounts
            .clone_and_filter_for_vat(
                MAX_ALPENGLOW_VOTE_ACCOUNTS,
                self.minimum_vote_account_balance_for_vat(),
            );
        if AlpenglowEpochType::is_alpenglow_or_migration_epoch(self, rewarded_epoch) {
            reward_epoch_delegated_stakes.set(self, &filtered_distribution_vote_accounts);
        }
        let cached_vote_accounts =
            self.get_cached_vote_accounts(rewarded_epoch, &filtered_distribution_vote_accounts);
```

**File:** runtime/src/bank.rs (L1815-1846)
```rust
    /// process for the start of a new epoch
    fn process_new_epoch(
        &mut self,
        parent_epoch: Epoch,
        parent_slot: Slot,
        parent_capitalization: u64,
        parent_height: u64,
        reward_calc_tracer: Option<impl RewardCalcTracer>,
    ) {
        let epoch = self.epoch();
        let slot = self.slot();
        let thread_pool = rewards_calculation_thread_pool();

        let (_, apply_feature_activations_time_us) = measure_us!(
            thread_pool.install(|| { self.compute_and_apply_new_feature_activations() })
        );

        let mut rewards_metrics = RewardsMetrics::default();
        let NewEpochBundle {
            stake_history,
            unfiltered_distribution_vote_accounts,
            delegated_stakes,
            filtered_distribution_vote_accounts,
            rewards_calculation,
            calculate_activated_stake_time_us,
            update_rewards_with_thread_pool_time_us,
        } = self.compute_new_epoch_caches_and_rewards(
            thread_pool,
            parent_epoch,
            reward_calc_tracer,
            &mut rewards_metrics,
        );
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L803-820)
```rust
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

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L977-1002)
```rust
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

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L3528-3545)
```rust
    #[test]
    fn test_epoch_boundary() {
        let delegations = 100;
        let stake_lamports = 2_000_000_000;
        let stakes: Vec<_> = (0..delegations).map(|_| stake_lamports).collect();
        let (
            RewardBank {
                bank: bank1,
                voters,
                stakers,
                ..
            },
            _bank_forks,
        ) = create_reward_bank_with_specific_stakes(
            stakes,
            PartitionedEpochRewardsConfig::default().stake_account_stores_per_block,
            SLOTS_PER_EPOCH,
        );
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
