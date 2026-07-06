### Title
Staker Can Instantly Raise Commission to 100% via Commission Commitment, Stealing Pool Members' Yield - (File: src/staking/staking.cairo)

### Summary
A staker can exploit the `set_commission_commitment` + `set_commission` flow to instantly raise their commission from 0% to 100% after pool members have already delegated funds, stealing all future pool rewards. The commission commitment mechanism was designed to protect delegators, but it permits sudden commission increases up to `max_commission` with no minimum notice period or gradual-increase requirement.

### Finding Description
The `set_commission_commitment` function allows a staker to set a `max_commission` ceiling up to 10000 (100%), regardless of the current commission. The only constraint is `current_commission <= max_commission`. [1](#0-0) 

Once an active commitment exists, `update_commission` permits setting commission to **any value ≤ `max_commission`**, including values far above the current commission. The only guard is that the new value must differ from the old one: [2](#0-1) 

The commission change takes effect immediately in storage with no epoch delay: [3](#0-2) 

And is applied directly in the next reward calculation: [4](#0-3) 

The code itself acknowledges this gap with the comment: [5](#0-4) 

### Impact Explanation
**High — Theft of unclaimed yield.**

A malicious staker can drain all pool rewards from delegators in a single epoch. Pool members who delegated based on an advertised 0% commission receive zero yield while the staker captures 100% of the pool's share. The stolen amount scales with the total delegated balance and the epoch reward rate.

### Likelihood Explanation
**Medium.** Any staker who opens a delegation pool can execute this attack. The steps require only two on-chain transactions (set commitment, then raise commission) executable in the same block. No special access, leaked key, or external dependency is needed. The attack is economically rational when the pool has accumulated significant delegated stake.

### Recommendation
1. **Enforce a minimum notice period for commission increases**: require that `expiration_epoch` is at least `current_epoch + K` before a commitment that raises commission above the current rate becomes effective.
2. **Cap the per-epoch commission increase rate**: limit how much commission can increase in a single `set_commission` call (e.g., no more than X basis points per epoch).
3. **Apply commission changes with a K-epoch delay** (analogous to how balance changes are delayed), so delegators have time to exit before a higher commission takes effect.

### Proof of Concept
Attack sequence (all executable by the staker in two consecutive transactions):

1. Staker calls `stake(...)` and `set_commission(commission: 0)` — advertises 0% commission to attract delegators.
2. Pool members call `enter_delegation_pool(...)` — funds are locked in the staking contract.
3. Staker calls `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)`.
   - Passes because `current_commission (0) <= max_commission (10000)`. [6](#0-5) 
4. Staker calls `set_commission(commission: 10000)`.
   - Passes because `10000 <= 10000` (commitment check) and `10000 != 0` (same-value check). [7](#0-6) 
5. In the next reward distribution, `split_rewards_with_commission` is called with `commission = 10000`, so `commission_rewards = pool_rewards_including_commission` and `pool_rewards = 0`. [8](#0-7) 
6. All pool rewards flow to the staker; delegators receive nothing for that epoch.

### Citations

**File:** src/staking/staking.cairo (L745-747)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
        /// **Note**: Updating epoch info can impact the commission commitment expiration date.
```

**File:** src/staking/staking.cairo (L769-771)
```text
            let current_commission = staker_pool_info.commission();
            assert!(current_commission <= max_commission, "{}", Error::MAX_COMMISSION_TOO_LOW);
            assert!(expiration_epoch > current_epoch, "{}", Error::EXPIRATION_EPOCH_TOO_EARLY);
```

**File:** src/staking/staking.cairo (L1580-1597)
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
```

**File:** src/staking/staking.cairo (L1599-1600)
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
