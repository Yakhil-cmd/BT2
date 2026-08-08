Based on tracing the reward-to-lamport conversion path, this attack does not work because every division in the pipeline is a **floor** division, which is provably conservative and cannot produce a lamport surplus regardless of how many tiny delegations are created.

Key evidence:

1. **Points → rewards conversion** (per stake delegation) uses floor division: [1](#0-0) 
Since `sum(tower_points)` over all delegations exactly equals `point_value.points` by construction (each delegation's points are counted once, non-overlapping), the sum of `floor(tower_points_i * rewards / total_points)` over all `i` is mathematically guaranteed to be `<= rewards`. Splitting rewards among more, smaller delegations only ever *increases* rounding loss (burned dust), never creates a surplus.

2. **Commission split** also floors both shares independently and discards the remainder rather than rounding either side up: [2](#0-1) 
`mine + theirs <= on` always holds because both terms are floors of two fractions that sum exactly to `on`.

3. These per-delegation `staker_rewards`/`voter_rewards` values are what get accumulated into `RewardsAccumulator::reward_commissions` and `total_stake_rewards_lamports`: [3](#0-2) 

Because every stage floors rather than rounds, the sum `distributed_lamports + distributed_to_incinerator_lamports + burned_lamports + total_stake_rewards_lamports` is mathematically bounded above by `point_value.rewards`; the `assert!` in `distribute_reward_commissions` at [4](#0-3)  cannot be tripped by manipulating delegation count or size, since more/smaller delegations only accumulate more rounding-down loss, never rounding-up gain. Additionally, `commission_split` explicitly documents this design choice: "we intentionally discard any residual fractional lamports" [5](#0-4) . There is no code path where fractional remainders are credited to the commission collector instead of being dropped.

#No vulnerability found for this question.

### Citations

**File:** runtime/src/inflation_rewards/mod.rs (L299-306)
```rust
            // In tower, `points` still needs to be scaled by `point_value` to calculate this
            // `vote_state` earned.
            // The final unwrap is safe, as points_value.points is guaranteed to be non zero above.
            tower_points
                .checked_mul(u128::from(point_value.rewards))
                .expect("Rewards intermediate calculation should fit within u128")
                .checked_div(point_value.points)
                .unwrap()
```

**File:** runtime/src/inflation_rewards/mod.rs (L377-406)
```rust
fn commission_split(commission_bps: u16, on: u64) -> (u64, u64, bool) {
    const MAX_BPS: u16 = 10_000;
    const MAX_BPS_U128: u128 = MAX_BPS as u128;
    match commission_bps.min(MAX_BPS) {
        0 => (0, on, false),
        MAX_BPS => (on, 0, false),
        split => {
            let on = u128::from(on);
            // Calculate mine and theirs independently and symmetrically instead of
            // using the remainder of the other to treat them strictly equally.
            // In Tower, this is also to cancel the rewarding if either of the parties
            // should receive only fractional lamports, resulting in not being rewarded at all.
            // Thus, note that we intentionally discard any residual fractional lamports.
            let mine = on
                .checked_mul(u128::from(split))
                .expect("multiplication of a u64 and u16 should not overflow")
                / MAX_BPS_U128;
            let theirs = on
                .checked_mul(u128::from(
                    MAX_BPS
                        .checked_sub(split)
                        .expect("commission cannot be greater than MAX_BPS"),
                ))
                .expect("multiplication of a u64 and u16 should not overflow")
                / MAX_BPS_U128;

            (mine as u64, theirs as u64, true)
        }
    }
}
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L128-141)
```rust
impl RewardsAccumulator {
    fn add_reward(&mut self, reward: RewardAccumulation) {
        self.num_stake_rewards = self.num_stake_rewards.saturating_add(1);
        self.total_stake_rewards_lamports = self
            .total_stake_rewards_lamports
            .saturating_add(reward.stake_reward);
        if let Some((commission_pubkey, reward_commission)) = reward.commission {
            self.reward_commissions
                .entry(commission_pubkey)
                .and_modify(|dst_reward_commission| {
                    accumulate_lamports(&reward_commission, dst_reward_commission);
                })
                .or_insert(reward_commission);
        }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L397-408)
```rust
        // verify that we didn't pay any more than we expected to
        assert!(
            point_value.rewards
                >= distributed_lamports
                    + distributed_to_incinerator_lamports
                    + burned_lamports
                    + total_stake_rewards_lamports,
            "point_value={point_value:?}, distributed_lamports={distributed_lamports}, \
             distributed_to_incinerator_lamports={distributed_to_incinerator_lamports} \
             burned_lamports={burned_lamports}, \
             total_stake_rewards_lamports={total_stake_rewards_lamports}"
        );
```
