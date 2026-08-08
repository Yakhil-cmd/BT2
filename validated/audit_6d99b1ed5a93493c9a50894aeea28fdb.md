### No vulnerability found for this question.

The described exploit is blocked by the exact clamp inside `adjust_delegation_for_rent`, which computes the new delegation as `std::cmp::min(new_delegation_with_rewards, lamports_with_rewards.saturating_sub(minimum_lamports))` [1](#0-0) . This `min()` guarantees `new_stake.delegation.stake <= account.lamports() - minimum_balance` unconditionally — it can only ever shrink the delegation toward the account's *current* lamport balance at distribution time, never inflate it beyond what the account actually holds.

Critically, `build_updated_stake_reward` re-reads `account.lamports()` fresh from `stakes_cache_accounts` at distribution time (not a stale calculation-time snapshot), so any withdrawal the attacker performs between calculation and distribution is reflected in the clamp computation [2](#0-1) . In the zero-stake placeholder path (`redeem_delegation_rewards`, vote-account-cache-miss branch), the stored `inflation.stake` is the *unmodified original* `stake` value with `stake_reward: 0` [3](#0-2) , so `delegation_with_rewards` passed into the distribution-time clamp is just the pre-existing (unadjusted) delegation — there is no reward-derived increase for the clamp to inconsistently apply.

Consequently, withdrawing lamports toward `minimum_lamports` before distribution can only cause the delegation to be reduced (and potentially deactivated, per lines 67-74) — never increased beyond what is backed by the account's real lamports. The `delegation_may_need_adjustment` function in `runtime/src/inflation_rewards/mod.rs:177-194` similarly only flags cases where the *correct* (shrunk) delegation differs from the current one; it does not itself write any inflated value. No path here produces delegation credit exceeding actual backing lamports minus rent-exempt reserve, so the claimed "minting" of stake weight does not occur.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L55-76)
```rust
fn adjust_delegation_for_rent(
    delegation: &mut Delegation,
    rewarded_epoch: Epoch,
    new_delegation_with_rewards: u64,
    lamports_with_rewards: u64,
    minimum_lamports: u64,
) {
    let new_delegation = std::cmp::min(
        new_delegation_with_rewards,
        lamports_with_rewards.saturating_sub(minimum_lamports),
    );

    if new_delegation != delegation.stake {
        delegation.stake = new_delegation;
        // Deactivate stake if needed. This deactivation is immediate,
        // unlike a requested deactivation which happens at the next epoch
        // boundary
        if new_delegation == 0 {
            delegation.deactivation_epoch = rewarded_epoch;
        }
    }
}
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L269-283)
```rust
        let mut new_stake = partitioned_stake_reward.inflation.stake;
        if adjust_delegations_for_rent {
            let minimum_balance = rent.minimum_balance(account.data().len());
            // The rewarded epoch is right before the distribution epoch
            let rewarded_epoch = distribution_epoch.saturating_sub(1);
            // The entry in `partitioned_stake_reward` contains the rewards,
            // calculated during the calculation phase
            let delegation_with_rewards = new_stake.delegation.stake;
            adjust_delegation_for_rent(
                &mut new_stake.delegation,
                rewarded_epoch,
                delegation_with_rewards,
                account.lamports(),
                minimum_balance,
            );
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L673-692)
```rust
                    );
                    let inflation = InflationReward {
                        stake,
                        stake_reward: 0,
                        commission_bps: (!custom_commission_collector).then_some(0),
                    };
                    // Set `is_vote_account` to `false` in order to deliberately
                    // fail during commission collector checks. This avoids
                    // creating a reward entry during payout.
                    let reward_commission = RewardCommission {
                        commission_bps: (!custom_commission_collector).then_some(0),
                        commission_lamports: 0,
                        burned_lamports: 0,
                        is_vote_account: false,
                    };
                    return Some(InflationRewardWithCommission {
                        inflation,
                        commission_pubkey: vote_pubkey,
                        reward_commission,
                    });
```
