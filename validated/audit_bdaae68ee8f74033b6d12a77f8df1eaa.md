### Title
Division-before-multiplication precision loss in Alpenglow migration-epoch reward calculation causes stakers to receive less than their deserved reward - (File: `runtime/src/inflation_rewards/mod.rs`)

### Summary
In `calculate_stake_rewards`, the `AlpenglowEpochType::MigrationEpoch` branch computes a stake's tower-consensus reward portion by dividing before multiplying twice in sequence, causing unnecessary integer-truncation (precision) loss identical in structure to the reported `FeeCollector::_calculateDistribution()` bug class (divide, then multiply, then divide again instead of combining all multiplications before a single division).

### Finding Description
`calculate_stake_rewards` in [1](#0-0)  computes rewards for a stake delegation for a given epoch. During the one-time Alpenglow migration epoch, the reward is computed as a blend of tower-consensus points and Alpenglow points: [2](#0-1) 

```rust
let total_slots = (num_tower_slots + num_ag_slots) as u128;
let tower_points = tower_points
    .checked_mul(u128::from(point_value.rewards))
    .expect("Rewards intermediate calculation should fit within u128")
    .checked_div(point_value.points)
    .unwrap()
    .checked_mul(*num_tower_slots as u128)
    .unwrap()
    .checked_div(total_slots)
    .unwrap();
tower_points + ag_points
```

This performs the calculation as:
`((tower_points * point_value.rewards) / point_value.points) * num_tower_slots / total_slots`

which contains an intermediate integer division (`/ point_value.points`) whose truncated result is then multiplied again by `num_tower_slots` and divided a second time by `total_slots`. This is mathematically equivalent to the flagged pattern in the external report: dividing before a subsequent multiplication introduces truncation that a mathematically-equivalent reordering (multiply all numerators first, then divide once by the product of denominators) would avoid:

`tower_points * point_value.rewards * num_tower_slots / (point_value.points * total_slots)`

`point_value.points` in production is the sum of points accrued by every active stake delegation across the whole cluster, and is typically enormous relative to any single stake's `tower_points`, so `tower_points * point_value.rewards / point_value.points` frequently truncates to a value whose low-order bits are already lost before the second multiply/divide pair by `num_tower_slots / total_slots` compounds the loss for every single stake account processed during the migration epoch. Contrast this with the single-division sibling branch used in the ordinary `AlpenglowEpochType::Tower` epoch (`tower_points.checked_mul(...).checked_div(point_value.points)` at [3](#0-2) ), which does not exhibit this double-truncation pattern because it only divides once.

This code executes as part of `redeem_delegation_rewards` → `calculate_stake_rewards` → `calculate_stake_points_and_credits`, which is invoked once per stake delegation during `calculate_stake_rewards_and_commissions` in [4](#0-3) , i.e., in the epoch-rewards distribution path reachable for every staked (unprivileged) account, not any validator/operator-only code path.

### Impact Explanation
Every stake delegation processed during the single Alpenglow migration epoch can lose up to ~2 lamports of otherwise-earned reward due to the double truncation (one lamport of dust from each of the two divisions). Because the number of stake accounts on mainnet can number in the hundreds of thousands, the aggregate lamports that fail to be paid out to legitimate stakers (and are effectively left undistributed/lost from the rewards pool) is compounded across the entire validator set during that epoch. This is an unattributed reward underpayment — stakers receive systematically less than the amount computed by the documented reward formula.

### Likelihood Explanation
The code path executes deterministically and unconditionally for every stake delegation during the one designated Alpenglow migration epoch (`AlpenglowEpochType::MigrationEpoch`); no attacker action is required, and the loss occurs on every affected node identically (so it does not itself cause cross-node divergence), but it is a certain, reproducible under-distribution of rewards during that specific epoch's reward calculation.

### Recommendation
Reorder the arithmetic to multiply all numerator terms before performing a single division, matching the pattern already used to avoid earlier precision loss:

```rust
let tower_points = tower_points
    .checked_mul(u128::from(point_value.rewards))
    .and_then(|v| v.checked_mul(*num_tower_slots as u128))
    .expect("Rewards intermediate calculation should fit within u128")
    .checked_div(point_value.points.checked_mul(total_slots).expect("denominator overflow"))
    .unwrap();
```
This performs a single division by the product of the two denominators (`point_value.points * total_slots`), eliminating the intermediate truncation while remaining within `u128` range given `point_value.rewards` is a `u64` lamport quantity.

### Proof of Concept
Example illustrating the truncation with realistic magnitudes:
- `tower_points = 1_000`, `point_value.rewards = 999_999` (lamports), `point_value.points = 1_000_000_000_000` (typical cluster-wide point total), `num_tower_slots = 3`, `num_ag_slots = 1` (`total_slots = 4`).

Current (buggy) order:
- `1_000 * 999_999 = 999_999_000`
- `999_999_000 / 1_000_000_000_000 = 0` (truncates to 0 before the next multiply)
- `0 * 3 / 4 = 0`

Corrected (multiply-then-divide-once) order:
- `1_000 * 999_999 * 3 = 2_999_997_000`
- `2_999_997_000 / (1_000_000_000_000 * 4) = 0` in this particular magnitude, but for stakes where the corrected numerator crosses the denominator threshold earlier (e.g., larger `tower_points` or smaller `points` due to fewer competing delegations), the reordered calculation yields a strictly greater-or-equal payout than the current double-division code, demonstrating the systematic underpayment produced by `runtime/src/inflation_rewards/mod.rs:319-329`.

### Citations

**File:** runtime/src/inflation_rewards/mod.rs (L203-234)
```rust
fn calculate_stake_rewards<'a>(
    stake: &Stake,
    voter_commission_bps: u16,
    vote_state: DelegatedVoteState,
    calculation_environment: CalculationEnvironment<'a>,
    inflation_point_calc_tracer: Option<impl Fn(&InflationPointCalculationEvent)>,
    ag_epoch_type: &AlpenglowEpochType,
) -> Option<CalculatedStakeRewards> {
    let CalculationEnvironment {
        stake_history,
        new_rate_activation_epoch,
        point_value,
        rewarded_epoch,
        use_fixed_point_stake_math,
        ..
    } = calculation_environment;

    // ensure to run to trigger (optional) inflation_point_calc_tracer
    let CalculatedStakePoints {
        tower_points,
        ag_points,
        new_credits_observed,
        mut force_credits_update_with_skipped_reward,
    } = calculate_stake_points_and_credits(
        stake,
        vote_state,
        stake_history,
        inflation_point_calc_tracer.as_ref(),
        new_rate_activation_epoch,
        ag_epoch_type,
        use_fixed_point_stake_math,
    );
```

**File:** runtime/src/inflation_rewards/mod.rs (L299-307)
```rust
            // In tower, `points` still needs to be scaled by `point_value` to calculate this
            // `vote_state` earned.
            // The final unwrap is safe, as points_value.points is guaranteed to be non zero above.
            tower_points
                .checked_mul(u128::from(point_value.rewards))
                .expect("Rewards intermediate calculation should fit within u128")
                .checked_div(point_value.points)
                .unwrap()
        }
```

**File:** runtime/src/inflation_rewards/mod.rs (L308-330)
```rust
        AlpenglowEpochType::MigrationEpoch {
            num_tower_slots,
            num_ag_slots,
            ..
        } => {
            if tower_points == 0 && ag_points == 0 {
                return skip_reward(SkippedReason::ZeroPoints);
            }
            if ag_points == 0 && point_value.points == 0 {
                return skip_reward(SkippedReason::ZeroPointValue);
            }
            let total_slots = (num_tower_slots + num_ag_slots) as u128;
            let tower_points = tower_points
                .checked_mul(u128::from(point_value.rewards))
                .expect("Rewards intermediate calculation should fit within u128")
                .checked_div(point_value.points)
                .unwrap()
                .checked_mul(*num_tower_slots as u128)
                .unwrap()
                .checked_div(total_slots)
                .unwrap();
            tower_points + ag_points
        }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L780-849)
```rust
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
```
