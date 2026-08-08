This confirms the key finding: the stake program enforces a minimum delegation amount that bounds the attacker's ability to fragment stake into unbounded dust accounts.

### Title
Reward computation cost scales with stake-account count, not total stake, but is bounded by protocol-enforced minimum delegation - ([File: runtime/src/bank/partitioned_epoch_rewards/calculation.rs])

### Summary
`Bank::calculate_stake_rewards_and_commissions` and `calculate_reward_points_partitioned` iterate once per active stake delegation (`stake_delegations.par_iter()`), so per-account cost is real: an attacker who owns more stake-delegation accounts causes more per-account work during `begin_partitioned_rewards`/`process_new_epoch`. However, the stake program enforces `get_minimum_delegation` (1 SOL when `upgrade_bpf_stake_program_to_v5_is_active`, historically much smaller) plus a rent-exempt reserve on every delegated stake account, so the number of "dust" delegation accounts an attacker can create is capped by `attacker_total_lamports / minimum_delegation_plus_rent_exempt_reserve`, not unbounded.

### Finding Description
`calculate_stake_rewards_and_commissions` at [1](#0-0)  pre-allocates and iterates `stake_delegations` — one reward computation per delegation entry, as explicitly documented in the comment about "N stake delegations, where N is >1,000,000" at [2](#0-1) . Similarly, `calculate_reward_points_partitioned` iterates `stake_delegations.par_iter()` once per delegation at [3](#0-2) . This work happens inside `compute_new_epoch_caches_and_rewards`/`process_new_epoch`/`begin_partitioned_rewards` at [4](#0-3) , which executes synchronously during `Bank::new_from_parent` at the epoch boundary. So splitting a delegation into N accounts does turn 1 unit of real stake into N units of computed work — the claim that cost is per-account rather than per-lamport is accurate.

However, this is not "unbounded relative to real stake." Creating each additional delegated stake account requires: (1) a rent-exempt reserve for `StakeStateV2::size_of()`, and (2) a minimum delegated stake amount enforced by `get_minimum_delegation` — 1 SOL when the `upgrade_bpf_stake_program_to_v5` feature is active [5](#0-4) , and even pre-feature, splitting requires funding a new account's rent-exempt balance and enough lamports to remain a valid stake account. The CLI-level tooling explicitly enforces "need at least {stake_minimum_delegation} for minimum stake delegation" before allowing a `Split` [6](#0-5) , and the on-chain stake program's minimum-delegation invariant is the actual protocol-level bound (not just a CLI courtesy check). Consequently, the number of stake-delegation accounts scales linearly with `attacker_total_lamports / minimum_delegation`, i.e., it is bounded by real stake, contradicting the premise that dust accounts can be created "each still eligible for a reward computation" without bound. Ten thousand dust accounts would require roughly ten thousand SOL of genuinely delegated stake, which is itself real economic stake subject to normal stake-weighting and is not "dust" in the sense of being cheap to create at scale.

### Impact Explanation
No violation is demonstrated beyond the known, already-bounded linear cost of `O(number_of_delegations)` for epoch-boundary reward calculation, which is inherent to any validator with a large number of legitimately delegated stake accounts (this is why the code already parallelizes with `thread_pool.install` and rayon `par_iter`, and documents scaling to >1,000,000 delegations as an expected, supported case). The `epoch_rewards_calculation_cache` further deduplicates this computation across forks sharing a parent hash [7](#0-6) , so an attacker cannot force repeated recomputation via forking either. There is no path shown by which an attacker inflates the number of reward computations without a proportional, enforced minimum-stake cost, so no unbounded epoch-boundary halt or retransmit stall is achievable from unprivileged Split spamming alone.

### Likelihood Explanation
Not applicable — the described attack does not bypass any check; the minimum-delegation and rent-exempt-reserve requirements are protocol-enforced constraints that scale account count with real committed stake, not with attacker-controlled "dust."

### Recommendation
N/A — no code change indicated. The existing `get_minimum_delegation` and rent-exempt account minimums already provide the necessary bound. If further hardening is desired, cluster operators could consider lowering practical epoch-boundary latency via engineering optimization (e.g., higher parallelism, or a global-hardcoded cap on the number of delegations processed per epoch with deferred processing), but this is unrelated to any exploitable unprivileged vulnerability.

### Proof of Concept
Not applicable — no exploitable defect found; a benchmark test could be written to plot `begin_partitioned_rewards` wall time vs. delegation count, but it would only confirm the well-known, protocol-bounded linear-in-delegation-count scaling that requires proportional real stake, not an attacker-only cost amplification.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L329-346)
```rust
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
        drop(epoch_rewards_calculation_cache);
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L803-819)
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
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L978-1002)
```rust
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

**File:** runtime/src/bank.rs (L1793-1872)
```rust
        let (rewards_calculation, update_rewards_with_thread_pool_time_us) =
            measure_us!(self.calculate_rewards(
                &stake_history,
                stake_delegations,
                cached_vote_accounts,
                rewarded_epoch,
                reward_epoch_delegated_stakes,
                reward_calc_tracer,
                thread_pool,
                rewards_metrics,
            ));
        NewEpochBundle {
            stake_history,
            unfiltered_distribution_vote_accounts,
            delegated_stakes,
            filtered_distribution_vote_accounts,
            rewards_calculation,
            calculate_activated_stake_time_us,
            update_rewards_with_thread_pool_time_us,
        }
    }

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

        self.stakes_cache.activate_epoch(
            epoch,
            stake_history,
            unfiltered_distribution_vote_accounts,
            delegated_stakes,
        );

        // Save a snapshot of stakes for use in consensus and stake weighted networking
        let leader_schedule_epoch = self.epoch_schedule.get_leader_schedule_epoch(slot);
        let (_, update_epoch_stakes_time_us) = measure_us!(self.update_epoch_stakes(
            leader_schedule_epoch,
            Some(filtered_distribution_vote_accounts),
        ));

        // Distribute rewards commission to vote accounts and cache stake rewards
        // for partitioned distribution in the upcoming slots.
        let (epoch_rewards, begin_partitioned_rewards_time_us) =
            measure_us!(self.begin_partitioned_rewards(
                parent_epoch,
                parent_slot,
                parent_height,
                &rewards_calculation,
                &mut rewards_metrics,
                thread_pool,
            ));
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

**File:** cli/src/stake.rs (L2050-2059)
```rust
        let stake_minimum_delegation = rpc_client.get_stake_minimum_delegation().await?;
        if lamports < stake_minimum_delegation {
            let lamports = Sol(lamports);
            let stake_minimum_delegation = Sol(stake_minimum_delegation);
            return Err(CliError::BadParameter(format!(
                "need at least {stake_minimum_delegation} for minimum stake delegation, provided: \
                 {lamports}"
            ))
            .into());
        }
```
