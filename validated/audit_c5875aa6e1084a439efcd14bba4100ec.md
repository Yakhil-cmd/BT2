### Title
Unbounded stake-delegation set size can inflate epoch-boundary reward calculation into a consensus-critical, unmetered O(N) computation - (File: `runtime/src/bank.rs`, `runtime/src/bank/partitioned_epoch_rewards/calculation.rs`)

### Summary
Unlike vote accounts, which are explicitly capped and truncated at epoch boundaries (`MAX_ALPENGLOW_VOTE_ACCOUNTS` via `clone_and_filter_for_vat`), the set of stake-account delegations that participate in epoch reward calculation has no upper bound. Anyone can permissionlessly create new stake accounts and delegate them (paying only rent-exemption plus a fixed minimum delegation), growing the stake-delegation set without limit. This set is fully collected and iterated once per epoch, synchronously, inside the epoch-boundary block's bank processing, mirroring the CoreDAO `candidateSet`/`turnRound()` bug class: an attacker inflates an unbounded, permissionlessly-populated collection that a privileged/consensus-critical function must iterate over in full within a single block.

### Finding Description
At every epoch boundary, `Bank::process_new_epoch` calls `compute_new_epoch_caches_and_rewards`, which does: [1](#0-0) 

Here `stakes.stake_delegations_vec()` collects the *entire* stake-delegation map into a `Vec` for parallel processing (documented as itself taking meaningful wall time, ~200ms, purely for the collection step) and feeds it into `calculate_activated_stake`: [2](#0-1) 

Note only vote accounts are filtered/truncated for reward purposes via SIMD-0357 VAT filtering: [3](#0-2) [4](#0-3) 

No equivalent cap exists for `stake_delegations`. The full, unfiltered `stake_delegations` vector is passed into `calculate_rewards` → `calculate_rewards_for_partitioning` → `calculate_validator_rewards`, which runs two full O(N) passes over every stake delegation in the cluster: [5](#0-4) [6](#0-5) 

The code itself acknowledges scaling concerns in a comment ("For N stake delegations, where N is >1,000,000...") but does not impose any hard limit on N: [7](#0-6) 

Critically, this *calculation* phase (unlike the *distribution* phase, which is deliberately spread over multiple blocks via `get_reward_distribution_num_blocks`/`partitioned_rewards_stake_account_stores_per_block`) happens entirely within the single epoch-boundary block: [8](#0-7) 

Stake account creation and delegation is a normal, unprivileged, permissionless transaction path (`CreateAccount`/`CreateAccountWithSeed` + `DelegateStake`), gated only by rent exemption and a fixed minimum delegation amount: [9](#0-8) 

This is structurally the same bug class as the CoreDAO report: an unbounded, permissionlessly-grown collection (`candidateSet` / `stake_delegations`) is iterated in full by a periodic, consensus-critical function (`turnRound()` / epoch-boundary `process_new_epoch`) with no maximum-count safeguard, unlike the sibling collection (vote accounts) which *does* have such a safeguard.

### Impact Explanation
If the stake-delegation count grows large enough, the O(N) calculation work in `calculate_reward_points_partitioned` and `calculate_stake_rewards_and_commissions`, plus the O(N) `stake_delegations_vec()` collection and `calculate_activated_stake`, must all complete within the epoch-boundary block's processing budget. Because this work is not partitioned across multiple blocks (unlike reward *distribution*), sufficiently inflating N could cause the epoch-boundary block to take excessively long to process, risking validators falling behind or missing slot deadlines around every epoch boundary — a recurring, network-wide liveness/performance degradation rather than a one-off failure. This is analogous to, but less severe than, the CoreDAO impact rating of "essentially making turnRound() inoperable," since Agave's slot-based architecture provides some resilience but the epoch-boundary computation itself is not resource-bounded like reward distribution is.

### Likelihood Explanation
Growing the stake-delegation set requires the attacker to fund one rent-exempt stake account (rent-exempt reserve for `StakeStateV2`) plus the minimum delegation (`get_minimum_delegation`, currently 1 SOL when the relevant feature is active) per delegation. This is a real economic cost, similar in nature to the CoreDAO `requiredMargin` deposit that the original report acknowledged and still rated as impactful (impact 4, likelihood 2). Reaching counts in the hundreds of thousands to millions (the threshold the code comments themselves flag) would require substantial capital, making this a lower-likelihood but non-trivial griefing vector, especially as SOL price or delegation minimums decrease over time.

### Recommendation
Introduce an explicit cap on the number of stake delegations considered during epoch-boundary reward calculation, analogous to `MAX_ALPENGLOW_VOTE_ACCOUNTS`/`clone_and_filter_for_vat` for vote accounts, or otherwise bound/partition the O(N) calculation phase (not just the distribution phase) across multiple blocks so no single block's processing time scales unboundedly with the total number of stake accounts in the cluster.

### Proof of Concept
Not applicable in the strict sense of a single malicious transaction achieving fund movement or halt; the scenario requires repeated, funded `CreateAccount`/`DelegateStake` transactions over time to grow `stake_delegations` to a size where `stake_delegations_vec()` collection (`runtime/src/stakes.rs:689`) and the two O(N) reward-calculation passes (`runtime/src/bank/partitioned_epoch_rewards/calculation.rs:942-1009`, `:780-938`) impose meaningful additional per-epoch-boundary-block latency, analogous to the CoreDAO PoC that registered many candidates via repeated `register()` calls to inflate `candidateSet` before `turnRound()`.

### Citations

**File:** runtime/src/bank.rs (L1762-1778)
```rust
        let stakes = self.stakes_cache.stakes();
        let stake_delegations = stakes.stake_delegations_vec();
        let (
            (
                stake_history,
                unfiltered_distribution_vote_accounts,
                delegated_stakes,
                reward_epoch_delegated_stakes,
            ),
            calculate_activated_stake_time_us,
        ) = measure_us!(stakes.calculate_activated_stake(
            self.epoch(),
            thread_pool,
            self.new_warmup_cooldown_rate_epoch(),
            &stake_delegations,
            self.use_fixed_point_stake_math(),
        ));
```

**File:** runtime/src/bank.rs (L1783-1787)
```rust
        let filtered_distribution_vote_accounts = unfiltered_distribution_vote_accounts
            .clone_and_filter_for_vat(
                MAX_ALPENGLOW_VOTE_ACCOUNTS,
                self.minimum_vote_account_balance_for_vat(),
            );
```

**File:** runtime/src/stakes.rs (L677-691)
```rust
    /// Collects stake delegations into a vector, which then can be used for
    /// parallel iteration with [`rayon`].
    ///
    /// # Performance
    ///
    /// The execution of this method takes ~200ms and it collects elements of
    /// the [`imbl::HashMap`], which is a [hash array mapped trie (HAMT)][hamt],
    /// so that operation involves a depth-first traversal with jumps. However,
    /// it's still a reasonable tradeoff if the caller iterates over these
    /// elements.
    ///
    /// [hamt]: https://en.wikipedia.org/wiki/Hash_array_mapped_trie
    pub(crate) fn stake_delegations_vec(&self) -> Vec<(&Pubkey, &StakeAccount)> {
        self.stake_delegations.iter().collect()
    }
```

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

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L803-928)
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
                    let block_reward = if block_revenue_sharing {
                        calculate_block_reward(
                            rewarded_epoch,
                            stake_account.delegation(),
                            stake_history,
                            cached_vote_accounts.distribution_epoch_vote_accounts,
                            ag_epoch_type,
                            new_warmup_cooldown_rate_epoch,
                            use_fixed_point_stake_math,
                        )
                    } else {
                        0
                    };
                    let maybe_reward_record = self.redeem_delegation_rewards(
                        rewarded_epoch,
                        stake_pubkey,
                        stake_account,
                        &point_value,
                        stake_history,
                        &cached_vote_accounts,
                        reward_calc_tracer.as_ref(),
                        new_warmup_cooldown_rate_epoch,
                        delay_commission_updates,
                        commission_rate_in_basis_points,
                        adjust_delegations_for_rent,
                        ag_epoch_type,
                        custom_commission_collector,
                        use_fixed_point_stake_math,
                    );

                    let (reward, maybe_reward_record) = match (block_reward, maybe_reward_record) {
                        (0, None) => (None, None),
                        (_, Some(res)) => {
                            let InflationRewardWithCommission {
                                inflation,
                                commission_pubkey,
                                reward_commission,
                            } = res;
                            let stake_reward = inflation.stake_reward;
                            (
                                Some(PartitionedStakeReward {
                                    stake_pubkey: **stake_pubkey,
                                    inflation,
                                    block_reward,
                                }),
                                Some(RewardAccumulation {
                                    stake_reward,
                                    commission: Some((commission_pubkey, reward_commission)),
                                }),
                            )
                        }
                        (_, None) => {
                            // Create a zero entry for distribution
                            let stake = *stake_account.stake();
                            let stake_reward = 0;
                            (
                                Some(PartitionedStakeReward {
                                    stake_pubkey: **stake_pubkey,
                                    inflation: InflationReward {
                                        stake,
                                        stake_reward,
                                        commission_bps: None,
                                    },
                                    block_reward,
                                }),
                                // Need a reward record for accumulator
                                Some(RewardAccumulation {
                                    stake_reward,
                                    commission: None,
                                }),
                            )
                        }
                    };
                    // It's important that for every stake delegation, we write
                    // a value to the cell of the stake rewards vector,
                    // regardless of whether it's `Some` or `None` variant.
                    // This allows us to pre-allocate the vector with the known
                    // size and avoid re-allocations, which were the bottleneck
                    // in this path.
                    reward_ref.write(reward);
                    maybe_reward_record
                })
                .fold(
                    RewardsAccumulator::default,
                    |mut rewards_accumulator, accumulation| {
                        rewards_accumulator.add_reward(accumulation);
                        rewards_accumulator
                    },
                )
                .reduce(
                    RewardsAccumulator::default,
                    |rewards_accumulator_a, rewards_accumulator_b| {
                        rewards_accumulator_a.accumulate_into_larger(rewards_accumulator_b)
                    },
                )
        });
        let RewardsAccumulator {
            reward_commissions,
            num_stake_rewards,
            total_stake_rewards_lamports,
        } = rewards_accumulator;
        // SAFETY: We initialized all the `stake_rewards` elements up to
        // `stake_delegations_len` (one cell per delegation, `Some` or `None`).
        // `num_stake_rewards` is the count of the `Some` cells.
        unsafe {
            stake_rewards.assume_init(num_stake_rewards, stake_delegations_len);
        }
        measure_redeem_rewards.stop();
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L940-1002)
```rust
    /// Calculates epoch reward points from stake/vote accounts.
    /// Returns reward lamports and points for the epoch or none if points == 0.
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
