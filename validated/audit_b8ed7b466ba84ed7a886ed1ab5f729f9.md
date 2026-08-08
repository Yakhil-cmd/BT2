## Title
Per-slot integer division in Alpenglow validator/leader reward calculation causes cumulative reward loss over an epoch - (File: `runtime/src/block_component_processor/vote_reward.rs`)

## Summary
The Alpenglow reward-calculation function `calculate_reward` computes a validator's (and leader's) per-slot reward payout using a single `u128` integer division, and this function is invoked independently for every reward-eligible slot in the epoch. Because the division rounds down and the same truncated ratio is applied on every slot of the epoch, the rounding error is effectively multiplied by `slots_per_epoch`, exactly matching the bug class described in the referenced report (`rewardRate` computed via integer division and then multiplied by duration).

## Finding Description
`calculate_reward` computes the per-slot reward for a validator as: [1](#0-0) 

```
numerator   = max_possible_validator_reward * validator_stake_lamports
denominator = slots_per_epoch * total_stake_lamports
reward_lamports = numerator / denominator   // u128 division, rounds down
```

This is documented in the code itself as being mathematically equivalent to first computing `per_slot_inflation = epoch_validator_rewards_lamports / slots_per_epoch` and then multiplying by the validator's stake fraction, just reordered for extra precision within a *single* slot's computation. However, `EpochInflationState` (`max_possible_validator_reward` and `slots_per_epoch`) is fixed for the entire epoch, and `calculate_reward` is re-invoked once per rewarded slot via `RewardState`/`calc_vote_rewards_update_vote_states`. Since the ratio `validator_stake_lamports / total_stake_lamports` does not change within an epoch for a given delegation snapshot, the same truncated `reward_lamports` value is produced and paid identically on every slot, so any single-slot rounding-down loss compounds `slots_per_epoch` times over the epoch — the same "rate rounds down, effect multiplied by duration" pattern as the referenced `StakingRewards.notifyRewardAmount` finding.

The repository's own test acknowledges this exact multiplicative truncation effect at the epoch level: [2](#0-1) 

```
let recorded_budget = ...inflation_rewards_for_epoch(bank.epoch())...
// Alpenglow rewards are rounded down once per slot, so this is the largest
// payout that can actually have been recorded during the epoch.
let recorded_payout = recorded_budget / SLOTS_PER_EPOCH * SLOTS_PER_EPOCH;
```

This test comment directly states that up to `SLOTS_PER_EPOCH - 1` lamports of the intended `max_possible_validator_reward` are unrecoverably lost every epoch due to the floor-division being repeated once per slot instead of tracking/accumulating the remainder.

## Impact Explanation
For validators whose `validator_stake_lamports / total_stake_lamports` ratio is small relative to `slots_per_epoch`, the per-slot `numerator / denominator` division can systematically round to a value smaller than the fair share, or even to zero, every single slot. Because this loss is not accumulated or redistributed (no fractional/remainder tracking mechanism exists analogous to the "accumulate the differences" mitigation suggested in the reference report), a meaningful fraction — potentially all — of the reward that should be paid out to lower-stake validators/leaders over an epoch is permanently and silently withheld rather than distributed, i.e., misattributed/lost validator rewards. This is directly analogous to the accepted impact category of "misattributed or duplicated rewards."

## Likelihood Explanation
This occurs on every epoch, for every validator, as a deterministic consequence of the arithmetic — no adversarial input is required. The magnitude of the loss scales with `slots_per_epoch` (very large, e.g. hundreds of thousands of slots) and is worse the smaller a validator's stake fraction is, making it most impactful for smaller/low-stake validators, similar to the "small token decimals" edge case called out by the original judges of the referenced finding.

## Recommendation
Track the fractional remainder from `numerator % denominator` across slots (or compute the epoch reward once and distribute the exact truncated remainder in a final settlement step, similar to the tower/point-value accounting already used elsewhere in the codebase, e.g. `PointValue`/`calculate_stake_rewards`), so that truncation happens at most once per epoch rather than compounding every slot.

## Proof of Concept
Given the test `test_alpenglow_partitioned_rewards_use_epoch_start_budget_after_burn`: [2](#0-1) 
With `recorded_budget` as the epoch-start inflation budget and `SLOTS_PER_EPOCH` the number of slots, `recorded_payout = recorded_budget / SLOTS_PER_EPOCH * SLOTS_PER_EPOCH` — i.e., up to `SLOTS_PER_EPOCH - 1` lamports (and proportionally more for lower-staked validators via `calculate_reward`'s combined numerator/denominator division) can never be paid out, matching the described precision-loss class where a per-unit-time rate rounds down and the effect is multiplied by the duration of the reward.

### Citations

**File:** runtime/src/block_component_processor/vote_reward.rs (L488-511)
```rust
fn calculate_reward(
    epoch_state: &EpochInflationState,
    total_stake_lamports: u64,
    validator_stake_lamports: u64,
) -> (u64, u64) {
    // Rewards are computed as following:
    // per_slot_inflation = epoch_validator_rewards_lamports / slots_per_epoch
    // fractional_stake = validator_stake / total_stake_lamports
    // rewards = fractional_stake * per_slot_inflation
    //
    // The code below is equivalent but changes the order of operations to maintain precision

    let numerator =
        epoch_state.max_possible_validator_reward as u128 * validator_stake_lamports as u128;
    let denominator = epoch_state.slots_per_epoch as u128 * total_stake_lamports as u128;

    // SAFETY: the result should fit in u64 because we do not expect the inflation in a single
    // epoch to exceed u64::MAX.
    let reward_lamports: u64 = (numerator / denominator).try_into().unwrap();
    // As per the Alpenglow SIMD, the rewards are split equally between the validators and the leader.
    let validator_reward_lamports = reward_lamports / 2;
    let leader_reward_lamports = reward_lamports - validator_reward_lamports;
    (validator_reward_lamports, leader_reward_lamports)
}
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L2824-2830)
```rust
        let recorded_budget = EpochInflationAccountState::new_from_bank(&bank)
            .and_then(|state| state.inflation_rewards_for_epoch(bank.epoch()))
            .expect("epoch-start inflation budget must be persisted");
        // Alpenglow rewards are rounded down once per slot, so this is the largest
        // payout that can actually have been recorded during the epoch.
        let recorded_payout = recorded_budget / SLOTS_PER_EPOCH * SLOTS_PER_EPOCH;

```
