### Title
Unchecked subtraction in `calc_earned_credits` can underflow and silently inflate stake/vote reward points - ([File: runtime/src/inflation_rewards/points.rs])

### Summary
The external report describes an unchecked arithmetic subtraction (`token1.decimals() - token0.decimals()`) that assumes a specific ordering between two values, causing an overflow/underflow when the assumption doesn't hold. The analogous pattern exists in Agave's stake reward/points calculation code: `calc_earned_credits` performs plain (non-`checked_sub`/non-`saturating_sub`) `u64` subtraction that assumes `final_epoch_credits >= initial_epoch_credits` and `final_epoch_credits >= *new_credits_observed`, without any code-level invariant enforcement local to this function.

### Finding Description
`calc_earned_credits` in `runtime/src/inflation_rewards/points.rs` computes the number of vote credits a stake account earned in a given epoch: [1](#0-0) 

The two subtractions:
```rust
let earned_credits = if credits_in_stake < initial_epoch_credits {
    final_epoch_credits - initial_epoch_credits
} else if credits_in_stake < final_epoch_credits {
    final_epoch_credits - *new_credits_observed
} else {
    0
};
```
use raw `u64` subtraction rather than `checked_sub`/`saturating_sub`. This function is called by `tower_epoch_credits_iter` [2](#0-1)  and by `calculate_alpenglow_points` [3](#0-2) , both of which feed into `calculate_stake_points_and_credits`, which is invoked from `calculate_stake_rewards` in `runtime/src/inflation_rewards/mod.rs` during epoch-boundary stake reward computation — an unprivileged-user-affecting accounting path that runs automatically for every stake/vote account pair at every epoch boundary.

In `tower_epoch_credits_iter`, `new_credits_observed` is updated across loop iterations via `new_credits_observed = new_credits_observed.max(final_epoch_credits)` (see the surrounding lines in `runtime/src/inflation_rewards/points.rs` lines 200-233 as fetched during investigation). If iteration order or epoch_credits entries are ever not strictly non-decreasing when this function is invoked — e.g., due to any inconsistency between the recorded `credits_observed` in the `Stake` account and the vote account's `epoch_credits` history (which can diverge across forks, snapshots, or during stake/vote account lifecycle operations such as deactivation/reactivation, delegation changes, or replaying a different set of `epoch_credits` entries than originally observed) — the subtraction `final_epoch_credits - *new_credits_observed` (or `final_epoch_credits - initial_epoch_credits`) can underflow.

Crucially, the workspace does not enable `overflow-checks = true` for release builds [4](#0-3) , meaning in a production (release) validator build, this underflow does not panic — it silently wraps around to a value close to `u64::MAX`, exactly mirroring the impact style of the reported bug (arithmetic performed on the wrong assumption of ordering, without protective checks).

### Impact Explanation
If `earned_credits` wraps to a near-`u64::MAX` value, it directly multiplies into the point calculation:
```rust
let earned_points = stake_amount * earned_credits;
points += earned_points;
```
This would produce an astronomically large `points` value for that stake/vote pair. Because rewards are eventually split proportionally to `points / total_points`, an inflated `points` value for one delegator would let that delegator claim a disproportionate (in the extreme, effectively all) share of the total inflation rewards for the epoch, functionally minting/misattributing lamports away from other stakers. This matches the "misattributed or duplicated rewards" acceptance criterion.

### Likelihood Explanation
This is a plausible-but-unproven analog: the code path is exercised on every epoch boundary for every stake account (a core, unprivileged accounting path — not validator/operator-role-gated), which raises the ceiling of "reachability," but I was not able to fully trace, within available time, a concrete scenario in current-code Solana/Agave stake-vote accounting where `credits_observed` recorded on a `Stake` account and the vote account's `epoch_credits` entries actually go out of the assumed monotonic order under normal (or even adversarial but permitted) usage. Vote program logic normally enforces strictly non-decreasing `epoch_credits` entries, and the `Ordering::Less`/`Ordering::Equal` early-return guard in `calculate_stake_points_and_credits` (lines 369-410) filters out the case where the *overall* vote credits are behind the stake's observed credits — but that guard operates on the *latest* vote credits total, not on each individual historical `epoch_credits` entry consumed inside `tower_epoch_credits_iter`'s loop, so it does not obviously rule out this per-entry underflow.

### Recommendation
Replace the raw subtraction operations in `calc_earned_credits` with `checked_sub` (returning an explicit error/None on violation) or, at minimum, `saturating_sub` with an accompanying invariant assertion/metric, so that any violation of the assumed ordering fails safely instead of silently wrapping in release builds. Additionally, add property-based tests that feed out-of-order or inconsistent `epoch_credits`/`credits_observed` combinations into `calc_earned_credits` and `tower_epoch_credits_iter` to confirm no silent wraparound is possible, and consider enabling `overflow-checks` in release profiles for critical reward-calculation crates as defense in depth.

### Proof of Concept
Not conclusively constructible from static analysis alone within the available investigation time. A full PoC would require demonstrating a concrete Bank/StakesCache/VoteAccount state where, at the point `calc_earned_credits` executes, `stake.credits_observed` is greater than `*new_credits_observed` (as carried from a prior loop iteration) while being less than the current entry's `final_epoch_credits`, or where an epoch_credits entry's `initial_epoch_credits` exceeds its own `final_epoch_credits`. I could not verify from the index whether existing vote-program invariants (enforced elsewhere, e.g., in `increment_credits`) preclude this entirely; a background engineer with full repo/test access should attempt to construct such a state (e.g., via crafted `VoteStateV4::epoch_credits` in a test bank, similar to the existing `test_tower_epoch_credits_iter` test at lines 537-606 of the same file) to confirm or refute reachability before treating this as a confirmed vulnerability.

### Citations

**File:** runtime/src/inflation_rewards/points.rs (L158-181)
```rust
fn calc_earned_credits(
    stake: &Stake,
    final_epoch_credits: u64,
    initial_epoch_credits: u64,
    new_credits_observed: &mut u64,
) -> u128 {
    let credits_in_stake = stake.credits_observed;

    // figure out how much this stake has seen that
    //   for which the vote account has a record
    let earned_credits = if credits_in_stake < initial_epoch_credits {
        // the staker observed the entire epoch
        final_epoch_credits - initial_epoch_credits
    } else if credits_in_stake < final_epoch_credits {
        // the staker registered sometime during the epoch, partial credit
        final_epoch_credits - *new_credits_observed
    } else {
        // the staker has already observed or been redeemed this epoch
        //  or was activated after this epoch
        0
    };
    *new_credits_observed = (*new_credits_observed).max(final_epoch_credits);
    u128::from(earned_credits)
}
```

**File:** runtime/src/inflation_rewards/points.rs (L187-234)
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

        if let Some(inflation_point_calc_tracer) = inflation_point_calc_tracer.as_ref() {
            inflation_point_calc_tracer(&InflationPointCalculationEvent::CalculatedPoints(
                epoch,
                stake_amount,
                earned_credits,
                earned_points,
            ));
        }
    }
    (points, new_credits_observed, saw_marker)
}
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

**File:** Cargo.toml (L1-1)
```text
[workspace]
```
