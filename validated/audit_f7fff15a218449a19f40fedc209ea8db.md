### Title
Staker Can Immediately Increase Commission Within Commitment Bounds, Front-Running Delegators' Epoch Reward Distribution — (File: src/staking/staking.cairo)

---

### Summary
A staker holding an active `CommissionCommitment` can raise their commission to `max_commission` at any time, and the change takes effect in the same block it is written. Because reward calculation reads the live commission value at distribution time, a staker can increase commission to 100% immediately before triggering reward distribution, causing delegators to receive zero rewards for the entire epoch. Delegators cannot exit in time due to the mandatory 1-week exit window.

---

### Finding Description

`set_commission` in `src/staking/staking.cairo` writes the new commission directly to storage with no delay: [1](#0-0) 

When an active `CommissionCommitment` exists, the only constraint is `commission <= max_commission` and `commission != old_commission` — an *increase* is explicitly permitted: [2](#0-1) 

The developers themselves flag this as a known gap: [3](#0-2) 

At reward-calculation time, `calculate_staker_pools_rewards` reads the live commission value: [4](#0-3) 

In the pre-consensus (attestation) path, rewards for the **entire epoch** are computed in a single call triggered by the staker's own attestation: [5](#0-4) 

The staker controls both the staker address (to call `set_commission`) and the operational address (to call `attest`). These two transactions can be submitted back-to-back in the same block, with no mechanism to prevent it.

Delegators cannot exit before the commission change takes effect. The exit path requires `exit_delegation_pool_intent` followed by a mandatory wait of at least `DEFAULT_EXIT_WAIT_WINDOW = 1 week`: [6](#0-5) 

The `set_commission_commitment` function allows `max_commission` up to `COMMISSION_DENOMINATOR` (10 000 = 100%): [7](#0-6) 

---

### Impact Explanation

**High — Theft of unclaimed yield.**

A staker can drain 100% of the pool's epoch rewards to themselves. Delegators who staked for the full epoch expecting a known commission rate receive zero rewards. The funds are not lost to the protocol; they are redirected to the staker's own `unclaimed_rewards_own`, constituting direct theft of delegators' unclaimed yield.

---

### Likelihood Explanation

- Any staker who has opened a delegation pool can execute this attack; no special privilege beyond owning the staker address is required.
- The commitment is public on-chain, but delegators have no on-chain mechanism to react before the commission change takes effect.
- The 1-week exit window makes it impossible for delegators to exit in response to a same-block commission increase.
- The staker controls attestation timing, giving precise control over when reward distribution is triggered.
- The attack is repeatable every epoch as long as a commitment is active or a new one is set.

---

### Recommendation

Commission *increases* should not take effect immediately. They should be deferred by at least K epochs (matching the existing pattern used for balance trace updates and token activation), giving delegators a predictable window to observe the change and exit if desired. Commission *decreases* can remain immediate, as they benefit delegators. This mirrors the two-step time-lock pattern recommended in the original report.

---

### Proof of Concept

1. Staker calls `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)`.
2. Delegators are staking in the pool at commission = 1000 (10%).
3. Near the end of the epoch, staker calls `set_commission(commission: 10000)`.
   - `update_commission` passes: `10000 <= 10000` (max_commission) and `10000 != 1000` (old).
   - `staker_pool_info.commission` is written to `10000` immediately.
4. Staker's operational address calls `attest(block_hash)` in the next transaction.
5. `update_rewards_from_attestation_contract` → `calculate_staker_pools_rewards` reads `commission = 10000`.
6. `split_rewards_with_commission(pool_rewards_including_commission, commission: 10000)` returns `(pool_rewards_including_commission, 0)`.
7. Pool contract receives 0 STRK; staker's `unclaimed_rewards_own` absorbs the full pool share.
8. Delegators call `claim_rewards` and receive 0 for the epoch.

### Citations

**File:** src/staking/staking.cairo (L74-75)
```text
    pub(crate) const DEFAULT_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: WEEK };
    pub(crate) const MAX_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: 12 * WEEK };
```

**File:** src/staking/staking.cairo (L745-747)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
        /// **Note**: Updating epoch info can impact the commission commitment expiration date.
```

**File:** src/staking/staking.cairo (L752-752)
```text
            assert!(max_commission <= COMMISSION_DENOMINATOR, "{}", Error::COMMISSION_OUT_OF_RANGE);
```

**File:** src/staking/staking.cairo (L1394-1423)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);

            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
            // Get current epoch data.
            let (strk_epoch_rewards, btc_epoch_rewards) = reward_supplier_dispatcher
                .calculate_current_epoch_rewards();
            let (strk_total_stake, btc_total_stake) = self.get_current_total_staking_power();
            let staker_pool_info = self.staker_pool_info.entry(staker_address).as_non_mut();
            let curr_epoch = self.get_current_epoch();
            self
                ._update_rewards(
                    :staker_address,
                    strk_total_rewards: strk_epoch_rewards,
                    btc_total_rewards: btc_epoch_rewards,
                    :strk_total_stake,
                    :btc_total_stake,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
        }
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
