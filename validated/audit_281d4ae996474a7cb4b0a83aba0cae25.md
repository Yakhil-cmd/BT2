### Title
`calculate_block_reward` can pay out more than `pending_delegator_rewards` in aggregate for a vote account when a delegator's effective stake grows between the initial reward calculation and a forced recalculation - (File: `runtime/src/bank/partitioned_epoch_rewards/calculation.rs`)

### Summary
`calculate_block_reward` explicitly acknowledges (in its own code comment) that during recalculation a single delegation's `stake` (from `delegation_effective_stake`) can exceed `total_active_stake` (frozen from `RewardEpochDelegatedStakes`), and clamps only that individual account's payout to `pending_delegator_rewards`. This per-account clamp does not protect the *sum* of block rewards paid to all delegators of the same vote account, so if one delegation's effective stake grows past the frozen total, its clamped share plus the other delegators' unclamped shares can exceed `pending_delegator_rewards` in total.

### Finding Description
In `runtime/src/bank/partitioned_epoch_rewards/calculation.rs`, `calculate_block_reward` computes: [1](#0-0) 
`total_active_stake` is looked up from `reward_epoch_delegated_stakes.delegated_stakes`, a value frozen at the end of the reward epoch, while `stake` is computed live via `delegation_effective_stake(delegation, rewarded_epoch, ...)`, which internally calls `Delegation::stake_v2`/`stake` using the delegation's *current* `stake` field (not a historical snapshot) combined with warmup/cooldown ratios derived from `stake_history` at `rewarded_epoch`.

Because `Delegation.stake` is a live, mutable field, any subsequent stake activity for that delegation (e.g., additional delegation/merge that increases `delegation.stake` for an account whose `activation_epoch` predates `rewarded_epoch`) will cause `delegation_effective_stake` computed *at the same historical epoch* to return a larger value than at the time `total_active_stake` was captured. The code's own comment confirms this is a known, reachable condition: "During recalculation, if stake account has already received rewards, it's possible to have `stake > total_active_stake`."

The per-call fix is `.min(pending_delegator_rewards)`, which bounds only the single delegator's payout, not the sum across all of the vote account's delegators. If delegator A's `stake` grows such that `stake_A > total_active_stake`, A's payout is clamped to the full `pending_delegator_rewards`. Meanwhile other delegators B, C, ... to the same vote account still receive `pending_delegator_rewards * stake_B / total_active_stake`, etc., computed independently in `calculate_stake_rewards_and_commissions`'s parallel iteration over `stake_delegations`, with no cross-account normalization or running total against `pending_delegator_rewards`. Consequently `sum(block_reward_i) = pending_delegator_rewards (for A, clamped) + Σ_{i≠A} pending_delegator_rewards * stake_i / total_active_stake`, which exceeds `pending_delegator_rewards` whenever `stake_i` for i≠A is not reduced to compensate — i.e., whenever the "conservation" invariant `Σ stake_i == total_active_stake` no longer holds because A's live stake grew after the snapshot.

This is reachable by an unprivileged attacker: they can delegate additional stake or perform a stake merge into an existing delegation account they control (delegated to any vote account, including one they don't control), timed so that a recalculation of stake rewards (`recalculate_stake_rewards` in the same file) is triggered via a reorg/skip-slot before the reward is finally distributed, causing `delegation_effective_stake` to be recomputed with the now-larger `delegation.stake` value against the old frozen `total_active_stake`.

The existing safety net — `.min(pending_delegator_rewards)` — is a per-delegator clamp only; it was added, per the comment, to prevent `u64` overflow/panic on the `try_into()`, not to enforce the cross-delegator sum invariant. No aggregate check exists in `calculate_stake_rewards_and_commissions` (`runtime/src/bank/partitioned_epoch_rewards/calculation.rs:780-917`) that caps the total block rewards paid out per vote account against that vote account's `pending_delegator_rewards`.

### Impact Explanation
This allows minting/over-distribution of lamports beyond what the vote account's `pending_delegator_rewards` bookkeeping counter represents: multiple stake accounts under the same vote account could, in aggregate, receive more block-reward lamports than the vote account ever recorded as pending for delegators, misattributing/duplicating reward lamports at distribution time (`build_updated_stake_reward` in `distribution.rs`, where `block_reward` is added to `stake_reward`).

### Likelihood Explanation
The precondition requires Alpenglow/MigrationEpoch (`block_revenue_sharing` feature) to be active and requires a delegator to have a stake delegation whose activation predates `rewarded_epoch`, then increase `delegation.stake` (via delegate/merge) between the initial computation and a forced recalculation trigger (reorg/skip-slot causing `recalculate_stake_rewards` to run again). This is a documented, self-acknowledged edge case in the code (the comment explicitly anticipates `stake > total_active_stake`), which increases confidence that the scenario is reachable in production under normal validator/consensus behavior (reorgs, skipped slots), not merely a theoretical construct — though it does require careful timing around a recalculation trigger and is not trivially exercisable on demand by an attacker without some fork/skip-slot event occurring.

### Recommendation
Enforce the invariant at the aggregate level rather than per-delegator: either (a) track the running sum of `block_reward` disbursed per vote account within `calculate_stake_rewards_and_commissions` and clamp remaining allocations to the remaining `pending_delegator_rewards` budget, or (b) recompute `total_active_stake` to reflect the true sum of currently effective delegations for that vote account at calculation/recalculation time so that `stake_i` values used are internally consistent with `total_active_stake` (avoiding stale snapshots being compared against live per-delegation state).

### Proof of Concept
Extend the existing `proptest!` block in `runtime/src/bank/partitioned_epoch_rewards/calculation.rs` (around `test_calculate_block_reward_prop`, lines 4334-4347) with a multi-delegator scenario:
```rust
proptest! {
    #[test]
    fn test_calculate_block_reward_sum_conservation(
        stake_a in 1..=u64::MAX,
        stake_b in 1..=u64::MAX,
        total_active_stake in 1..=u64::MAX,
        pending_delegator_rewards in 0..=u64::MAX,
        rewarded_epoch in 0..=solana_stake_history::MAX_ENTRIES as u64,
    ) {
        // Construct one vote account with pending_delegator_rewards, and
        // reward_epoch_delegated_stakes fixed at total_active_stake.
        // Build two delegations (A, B) to the same vote account, both fully
        // activated at rewarded_epoch (activation_epoch = u64::MAX i.e. bootstrap),
        // where stake_a is set to simulate a post-snapshot merge such that
        // stake_a > total_active_stake, and stake_b is any independent value.
        let reward_a = get_block_reward_for_test(stake_a, total_active_stake, pending_delegator_rewards, rewarded_epoch);
        let reward_b = get_block_reward_for_test(stake_b, total_active_stake, pending_delegator_rewards, rewarded_epoch);
        // Assert the aggregate invariant that the current code does NOT enforce:
        prop_assert!(reward_a + reward_b <= pending_delegator_rewards);
    }
}
```
Expected result: this test fails whenever `stake_a > total_active_stake` (clamping `reward_a` to `pending_delegator_rewards`) while `stake_b > 0`, demonstrating `reward_a + reward_b > pending_delegator_rewards`, confirming the sum-conservation invariant is violated by the current per-call clamp in `calculate_block_reward` (`runtime/src/bank/partitioned_epoch_rewards/calculation.rs:173-232`).

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L206-232)
```rust
    let total_active_stake = reward_epoch_delegated_stakes
        .delegated_stakes
        .get(&vote_pubkey)
        .copied()
        .unwrap_or(0);
    if total_active_stake == 0 {
        0
    } else {
        let stake = delegation_effective_stake(
            delegation,
            rewarded_epoch,
            stake_history,
            new_warmup_cooldown_rate_epoch,
            use_fixed_point_stake_math,
        );
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
    }
}
```
