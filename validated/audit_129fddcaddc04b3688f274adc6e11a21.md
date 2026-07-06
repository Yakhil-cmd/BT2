### Title
Staker Can Increase Commission Mid-Epoch to Steal Delegator Yield - (`src/staking/staking.cairo`)

### Summary
A staker holding an active `commission_commitment` can call `set_commission` to raise their commission rate at any point within an epoch, immediately before rewards are calculated. Because the commission is read from live storage at the moment of reward settlement, delegators who entered the pool at a lower commission rate lose a portion of the yield they earned during that epoch.

### Finding Description

The `set_commission` function writes the new commission directly to storage with no epoch delay: [1](#0-0) 

When `update_rewards_from_attestation_contract` (V2) or `update_rewards` (V3) is subsequently called, `calculate_staker_pools_rewards` reads the commission from storage at that instant: [2](#0-1) 

The `split_rewards_with_commission` helper then applies the current (post-change) commission to the full epoch's pool rewards: [3](#0-2) 

Without a commitment, `set_commission` only allows decreases: [4](#0-3) 

However, with an active `commission_commitment`, the staker may set commission to **any value ≤ `max_commission`**, including values higher than the commission in effect when delegators entered the pool: [5](#0-4) 

A commitment is created via `set_commission_commitment`, which only requires `max_commission ≥ current_commission`: [6](#0-5) 

**Attack sequence (V2 attestation path):**
1. Staker has commission = 1%. Calls `set_commission_commitment(max_commission=50%, expiration_epoch=E+5)`.
2. Delegators enter the pool, seeing commission = 1%.
3. Epoch N progresses. Delegators earn rewards at 1% commission.
4. Near the end of epoch N (before attesting), staker calls `set_commission(50%)`.
5. Staker attests, triggering `update_rewards_from_attestation_contract`.
6. Rewards for epoch N are split using 50% commission — delegators receive 49% less than earned.

In V3 (consensus rewards), `update_rewards` is callable by anyone, but the staker can still front-run it by changing commission in the same block or earlier in the same epoch.

### Impact Explanation

Delegators lose a portion of the yield they earned during the epoch. The staker captures the difference as commission. This is a direct theft of unclaimed yield from pool members. The magnitude scales with pool size and the commission delta (up to `max_commission - original_commission`).

**Impact: High — Theft of unclaimed yield.**

### Likelihood Explanation

Any staker who has set a `commission_commitment` with `max_commission > current_commission` can execute this. Commission commitments are a standard, documented protocol feature. The staker controls the timing of their attestation (V2) and can trivially time the commission change to precede it. No external conditions or special privileges are required beyond being a staker with an active commitment.

### Recommendation

Apply a one-epoch delay to commission increases. When `set_commission` raises the commission (within a commitment), the new rate should be stored with an effective epoch of `current_epoch + 1` (or `current_epoch + K`), consistent with how balance changes are deferred via the balance trace. Commission decreases can remain immediately effective since they benefit delegators.

### Proof of Concept

```
1. Staker stakes, sets commission = 100 (1%).
2. Staker calls set_commission_commitment(max_commission=5000, expiration_epoch=current+3).
3. Delegator enters pool. Pool balance = D.
4. Epoch N runs. Attestation window opens.
5. Staker calls set_commission(5000)  // 50%, within commitment
6. Staker attests → update_rewards_from_attestation_contract fires.
7. calculate_staker_pools_rewards reads commission = 5000.
8. split_rewards_with_commission(pool_rewards_including_commission, 5000)
   → commission_rewards = pool_rewards * 50%
   → pool_rewards sent to pool = pool_rewards * 50%
9. Delegator claims rewards: receives 50% of what they would have received at 1%.
   Staker captures the other 49% as commission.

Expected: delegator receives rewards at the commission rate in effect when they delegated.
Actual:   delegator receives rewards at the commission rate in effect at attestation time.
```

The root cause is at: [7](#0-6) 
— commission is read from live storage with no epoch-boundary guard — combined with the immediate write at: [1](#0-0)

### Citations

**File:** src/staking/staking.cairo (L769-771)
```text
            let current_commission = staker_pool_info.commission();
            assert!(current_commission <= max_commission, "{}", Error::MAX_COMMISSION_TOO_LOW);
            assert!(expiration_epoch > current_epoch, "{}", Error::EXPIRATION_EPOCH_TOO_EARLY);
```

**File:** src/staking/staking.cairo (L1580-1589)
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
```

**File:** src/staking/staking.cairo (L1595-1597)
```text
            } else {
                assert!(commission < old_commission, "{}", Error::INVALID_COMMISSION);
            }
```

**File:** src/staking/staking.cairo (L1599-1601)
```text
            // Update commission in storage.
            staker_pool_info.commission.write(Option::Some(commission));

```

**File:** src/staking/staking.cairo (L1964-1991)
```text
            let commission = staker_pool_info.commission();
            for (pool_contract, token_address) in staker_pool_info.pools {
                if !self.is_active_token(:token_address, epoch_id: curr_epoch) {
                    continue;
                }
                let pool_balance_curr_epoch = self
                    .get_staker_delegated_balance_at_epoch(
                        :staker_address, :pool_contract, epoch_id: curr_epoch,
                    );
                let (total_rewards, total_stake) = if token_address == STRK_TOKEN_ADDRESS {
                    (strk_total_rewards, strk_total_stake)
                } else {
                    (btc_total_rewards, btc_total_stake)
                };
                // Calculate rewards for this pool.
                let pool_rewards_including_commission = if total_stake.is_non_zero() {
                    mul_wide_and_div(
                        lhs: total_rewards,
                        rhs: pool_balance_curr_epoch.to_amount_18_decimals(),
                        div: total_stake.to_amount_18_decimals(),
                    )
                        .expect_with_err(err: InternalError::REWARDS_COMPUTATION_OVERFLOW)
                } else {
                    Zero::zero()
                };
                let (commission_rewards, pool_rewards) = split_rewards_with_commission(
                    rewards_including_commission: pool_rewards_including_commission, :commission,
                );
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
