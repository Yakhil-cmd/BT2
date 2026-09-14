### Title
Incorrect `&&` guard before division causes divide-by-zero panic in Alpenglow migration-epoch reward calculation - (File: `runtime/src/inflation_rewards/mod.rs`)

### Summary
`calculate_stake_rewards` in `runtime/src/inflation_rewards/mod.rs` handles the `AlpenglowEpochType::MigrationEpoch` branch by guarding a subsequent division with two `&&`-joined zero-checks instead of the `||` logic required to fully protect the division that follows.

### Finding Description
In the `MigrationEpoch` arm of `calculate_stake_rewards`, the code is:

```rust
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
    ...
``` [1](#0-0) 

The division `checked_div(point_value.points)` is only safe when `point_value.points != 0`. However, the guard preceding it is `ag_points == 0 && point_value.points == 0` — an AND of two conditions — rather than a check on `point_value.points == 0` alone (or an OR of the two). If `point_value.points == 0` while `ag_points != 0` (and/or `tower_points != 0`), neither of the two early-return guards fires, and execution falls through to `checked_div(point_value.points).unwrap()`, which returns `None` on division by zero and panics via `.unwrap()`.

This mirrors the external report's bug class exactly: a condition intended to gate a "reject if either value is zero" scenario incorrectly requires *both* values to be zero (`&&` instead of `||`), and the failure path leads to unchecked continuation (here, an `unwrap()` panic) rather than a safe/guarded outcome.

### Impact Explanation
A panic inside bank reward calculation at an Alpenglow migration epoch boundary would abort/crash the validator process executing this code path (this runs deterministically for every validator processing the same epoch-boundary reward calculation), which is a transaction-triggered/consensus-path cluster halt/panic condition if such a `point_value.points == 0` / nonzero-points mismatch state is reachable. That would satisfy the "transaction-triggered cluster halt" acceptance criterion.

### Likelihood Explanation
I could not fully verify whether `point_value.points == 0` together with nonzero individual `tower_points`/`ag_points` for a given stake is actually reachable in practice. From what I could inspect, `point_value.points` is the total tower-epoch point denominator accumulated bank-wide (via `calculate_points`/reward calculation flow in `runtime/src/bank/partitioned_epoch_rewards/calculation.rs`), and it is normally expected to be the sum of all individual stakes' points, which would make a "nonzero individual points, zero total points" state mathematically inconsistent under normal computation. I was not able to trace the exact code path that assembles `point_value.points` from individual `tower_points` to confirm whether an inconsistency (e.g., a stale/cached or partially-computed `point_value` used against a freshly recomputed `tower_points`, as happens during "recalculation" flows referenced in `runtime/src/bank/partitioned_epoch_rewards/calculation.rs` around `test_recalculate_alpenglow_rewards_after_partial_distribution_uses_original_denominator`) could produce such a mismatch. This uncertainty prevents me from confirming concrete reachability from a single submitted transaction or even from validator-only automatic epoch-boundary processing.

### Recommendation
Change the guard to check `point_value.points == 0` directly (regardless of `ag_points`), e.g.:
```rust
if point_value.points == 0 {
    return skip_reward(SkippedReason::ZeroPointValue);
}
```
so the division is always protected against a zero denominator, matching the semantics implied by the analogous Vyper fix (checking the failure condition with `||` rather than requiring both values to be zero via `&&`).

### Proof of Concept
Not concretely demonstrated — I could not confirm a code path that produces `point_value.points == 0` with a nonzero per-stake `tower_points`/`ag_points` for the same calculation. A concrete PoC would require constructing bank state at an Alpenglow migration-epoch boundary where the aggregate point denominator (`point_value.points`) is zero while an individual stake's recomputed `tower_points` is nonzero (e.g. via the partial-distribution recalculation path in `runtime/src/bank/partitioned_epoch_rewards/calculation.rs`), then observing the `unwrap()` panic in `runtime/src/inflation_rewards/mod.rs` during reward computation for that epoch. [2](#0-1) [3](#0-2)

### Citations

**File:** runtime/src/inflation_rewards/mod.rs (L304-326)
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

**File:** runtime/src/alpenglow_epoch_type.rs (L153-169)
```rust
#[derive(Debug)]
pub(crate) enum AlpenglowEpochType<'a> {
    /// This is a full tower epoch.
    Tower,
    /// The epoch started in tower and then switched to alpenglow
    MigrationEpoch {
        num_tower_slots: Slot,
        num_ag_slots: Slot,
        migration_epoch: Epoch,
        reward_epoch_delegated_stakes: &'a RewardEpochDelegatedStakes,
    },
    /// This is a full alpenglow epoch
    Alpenglow {
        migration_epoch: Epoch,
        reward_epoch_delegated_stakes: &'a RewardEpochDelegatedStakes,
    },
}
```
