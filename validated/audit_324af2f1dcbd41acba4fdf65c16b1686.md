### Title
Staker Can Immediately Increase Commission Before Reward Distribution to Steal Delegator Yield - (File: `src/staking/staking.cairo`)

### Summary
`set_commission()` applies a new commission value to storage with no delay. When a staker holds an active `CommissionCommitment` that permits commission increases, they can raise commission to `max_commission` at any moment. The very next `update_rewards()` or `update_rewards_from_attestation_contract()` call will split pool rewards using the new, higher commission, transferring yield that delegators expected to receive directly to the staker.

### Finding Description
`set_commission()` writes the new commission value immediately to storage with no epoch-delay or ramping mechanism: [1](#0-0) 

When an active `CommissionCommitment` exists, the only constraint is `commission <= max_commission` and `commission != old_commission`. There is no lower-bound check — the staker may freely increase commission up to `max_commission`: [2](#0-1) 

`max_commission` itself is uncapped up to `COMMISSION_DENOMINATOR` (10 000 = 100%): [3](#0-2) 

At reward-distribution time, `calculate_staker_pools_rewards()` reads commission directly from storage: [4](#0-3) 

The code itself acknowledges the gap: [5](#0-4) 

### Impact Explanation
A staker who raises commission to 100% immediately before `update_rewards()` is called causes `split_rewards_with_commission` to route the entire pool-share of block rewards to the staker as commission, leaving delegators with zero yield for that distribution. Because delegators are locked behind an exit-wait window of at least one week, they cannot exit before the change takes effect. This constitutes **theft of unclaimed yield** from delegators.

### Likelihood Explanation
The attack requires only that the staker:
1. Set a `CommissionCommitment` with a high `max_commission` (up to 100%) — a public, permissionless action.
2. Advertise a low commission (e.g. 0%) to attract delegators.
3. Call `set_commission(max_commission)` at any time before the next `update_rewards()` block.

No privileged access beyond owning the staker address is needed. The staker address is explicitly listed as a valid attacker in the bounty scope. The attack is repeatable every block.

### Recommendation
Introduce an epoch-delay for commission increases analogous to the existing `K`-epoch delay used for balance changes. When `set_commission()` is called with a value higher than the current commission, record the pending new commission and the epoch at which it becomes effective (`current_epoch + K`). `calculate_staker_pools_rewards()` should read the commission that was active at `curr_epoch`, not the latest stored value. This mirrors how balance traces already defer the effect of stake changes by `K` epochs: [6](#0-5) 

### Proof of Concept
```
1. Staker calls set_commission_commitment(max_commission=10000, expiration_epoch=E)
   → CommissionCommitment stored; max_commission = 100%.

2. Staker calls set_commission(commission=0)
   → Commission written to storage as 0%.
   → Delegators observe 0% commission and enter the pool.

3. Staker calls set_commission(commission=10000)
   → Passes: 10000 <= max_commission (10000) and 10000 != 0.
   → Commission written to storage as 10000% immediately.

4. Sequencer calls update_rewards(staker_address, disable_rewards=false)
   → calculate_staker_pools_rewards() reads commission = 10000.
   → split_rewards_with_commission(pool_rewards_including_commission, 10000)
     returns (commission_rewards = pool_rewards_including_commission, pool_rewards = 0).
   → Staker's unclaimed_rewards_own += full pool share.
   → Pool contract receives 0 STRK.

5. Delegators call claim_rewards() → receive 0 for this distribution period.
``` [7](#0-6) [8](#0-7)

### Citations

**File:** src/staking/staking.cairo (L73-73)
```text
    pub const COMMISSION_DENOMINATOR: Commission = 10000;
```

**File:** src/staking/staking.cairo (L745-747)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
        /// **Note**: Updating epoch info can impact the commission commitment expiration date.
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

**File:** src/staking/staking.cairo (L2004-2005)
```text
        fn get_epoch_plus_k(self: @ContractState) -> Epoch {
            self.get_current_epoch() + K.into()
```

**File:** src/staking/staking.cairo (L2348-2362)
```text
            // Update reward supplier.
            let staker_rewards = staker_own_rewards + commission_rewards;
            // Update total rewards.
            reward_supplier_dispatcher
                .update_unclaimed_rewards_from_staking_contract(
                    rewards: staker_rewards + total_pools_rewards,
                );
            // Claim pools rewards.
            claim_from_reward_supplier(
                :reward_supplier_dispatcher,
                amount: total_pools_rewards,
                token_dispatcher: strk_token_dispatcher(),
            );
            // Update staker rewards.
            staker_info.unclaimed_rewards_own += staker_rewards;
```
