### Title
Staker Can Instantly Increase Commission via Commitment to Steal Delegators' Unclaimed Yield - (File: src/staking/staking.cairo)

### Summary
A staker can attract delegators with a low commission, then use the `set_commission_commitment` + `set_commission` mechanism to instantly raise commission to up to 100% before rewards are distributed, stealing delegators' unclaimed yield. The protocol's own code acknowledges this: `"Current commission increase safeguards still allow for sudden commission changes."` [1](#0-0) 

### Finding Description
The `set_commission_commitment` function allows a staker to set a `max_commission` value that is **higher** than the current commission. [2](#0-1) 

Once a commitment is active, `set_commission` (via `update_commission`) permits the staker to set commission to **any value up to `max_commission`** with no delay or timelock: [3](#0-2) 

The new commission is written to storage immediately: [4](#0-3) 

When rewards are distributed via attestation, `split_rewards_with_commission` uses the **current** commission from storage, so the staker captures the full commission share at the elevated rate: [5](#0-4) 

Delegators who entered the pool during the exit wait window cannot exit before the commission change takes effect, and they have no slippage protection on the commission rate applied to their rewards.

**Attack path:**
1. Staker deploys pool with commission = 0 (or a low value), attracting delegators.
2. Staker calls `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)`. The commitment is valid for one epoch. [6](#0-5) 
3. Staker immediately calls `set_commission(10000)` — commission jumps to 100% in the same block.
4. When the attestation contract triggers reward distribution, `split_rewards_with_commission` applies 100% commission, sending all pool rewards to the staker and zero to delegators. [7](#0-6) 
5. Delegators are locked in the pool for the full exit wait window (`DEFAULT_EXIT_WAIT_WINDOW`) and cannot recover the stolen epoch's rewards. [8](#0-7) 

### Impact Explanation
**High — Theft of unclaimed yield.** Delegators who entered the pool expecting a low commission rate have their entire epoch's reward allocation redirected to the staker as commission. The funds are not recoverable; the delegators receive zero rewards for the affected epoch(s). The staker can repeat this pattern each time a new commitment window opens.

### Likelihood Explanation
**Medium.** The attack requires the staker to deliberately set a commitment with `max_commission` above the advertised rate, which is a visible on-chain action. However, the commitment window can be as short as one epoch, and the commission increase can be executed in the same block as the commitment is set. Delegators monitoring on-chain events may not react in time, especially since they are locked in the exit wait window. The protocol's own inline comment acknowledges the gap: `"Current commission increase safeguards still allow for sudden commission changes."` [1](#0-0) 

### Recommendation
Apply a time delay (at least one full epoch, or the exit wait window) between when a commission increase is committed and when it takes effect. This mirrors the standard timelock recommendation from the original report and gives delegators a window to exit before the higher commission applies. Alternatively, cap `max_commission` in a commitment to the current commission (i.e., commitments may only lock in the current rate or lower, not permit increases).

### Proof of Concept
```
// 1. Staker stakes and opens pool with commission = 0
staking.stake(reward_address, operational_address, amount);
staking.set_commission(commission: 0);
staking.set_open_for_delegation(token_address: STRK_TOKEN_ADDRESS);

// 2. Delegators enter the pool, expecting 0% commission
pool.enter_delegation_pool(pool_member: delegator, amount: X);

// 3. Staker sets commitment allowing up to 100% commission, valid for 1 epoch
staking.set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1);

// 4. Staker immediately raises commission to 100% — no delay enforced
staking.set_commission(commission: 10000);

// 5. Attestation fires; split_rewards_with_commission(total_rewards, 10000)
//    => commission_rewards = total_rewards, pool_rewards = 0
//    Delegators receive 0 STRK for this epoch.
attestation.attest(block_hash);

// 6. Delegators are trapped in the exit wait window; rewards already gone.
```

The `update_commission` path that permits this increase is: [9](#0-8)

### Citations

**File:** src/staking/staking.cairo (L74-74)
```text
    pub(crate) const DEFAULT_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: WEEK };
```

**File:** src/staking/staking.cairo (L745-746)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
```

**File:** src/staking/staking.cairo (L769-770)
```text
            let current_commission = staker_pool_info.commission();
            assert!(current_commission <= max_commission, "{}", Error::MAX_COMMISSION_TOO_LOW);
```

**File:** src/staking/staking.cairo (L771-778)
```text
            assert!(expiration_epoch > current_epoch, "{}", Error::EXPIRATION_EPOCH_TOO_EARLY);
            assert!(
                expiration_epoch - current_epoch <= self.get_epoch_info().epochs_in_year(),
                "{}",
                Error::EXPIRATION_EPOCH_TOO_FAR,
            );
            let commission_commitment = CommissionCommitment { max_commission, expiration_epoch };
            staker_pool_info.commission_commitment.write(Option::Some(commission_commitment));
```

**File:** src/staking/staking.cairo (L1580-1600)
```text
            if let Option::Some(commission_commitment) = staker_pool_info
                .commission_commitment
                .read() {
                if self.is_commission_commitment_active(:commission_commitment) {
                    assert!(
                        commission <= commission_commitment.max_commission,
                        "{}",
                        Error::INVALID_COMMISSION_WITH_COMMITMENT,
                    );
                    assert!(commission != old_commission, "{}", Error::INVALID_SAME_COMMISSION);
                } else {
                    assert!(
                        commission < old_commission, "{}", Error::COMMISSION_COMMITMENT_EXPIRED,
                    );
                }
            } else {
                assert!(commission < old_commission, "{}", Error::INVALID_COMMISSION);
            }

            // Update commission in storage.
            staker_pool_info.commission.write(Option::Some(commission));
```

**File:** src/staking/utils.cairo (L68-76)
```text
pub(crate) fn split_rewards_with_commission(
    rewards_including_commission: Amount, commission: Commission,
) -> (Amount, Amount) {
    let commission_rewards = compute_commission_amount_rounded_down(
        :rewards_including_commission, :commission,
    );
    let pool_rewards = rewards_including_commission - commission_rewards;
    (commission_rewards, pool_rewards)
}
```
