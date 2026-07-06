### Title
Commission Change Without Prior Reward Settlement Allows Staker to Retroactively Extract Delegator Yield - (File: `src/staking/staking.cairo`)

---

### Summary

`set_commission` updates the staker's commission rate immediately without first settling accumulated rewards at the old rate. Because reward calculation reads the commission at the moment of attestation/reward-update, a staker holding an active `CommissionCommitment` can raise their commission to `max_commission` immediately before attesting, causing the entire epoch's pool rewards to be split at the new (higher) rate — retroactively stealing yield from delegators.

---

### Finding Description

The vulnerability class is an **accounting bug**: a configuration parameter that affects reward distribution is mutated without first checkpointing the accumulated rewards under the old parameter value.

**Root cause — `set_commission` / `update_commission`**

`set_commission` (staking.cairo:725) delegates to `update_commission` (staking.cairo:1573). Neither function triggers a reward settlement before writing the new commission value: [1](#0-0) 

The function simply overwrites the stored commission with no prior call to distribute pending rewards.

**Where commission is consumed — `calculate_staker_pools_rewards`**

When rewards are eventually distributed (via `update_rewards_from_attestation_contract` in V2, or `update_rewards` in V3), the commission is read from storage at that instant: [2](#0-1) 

The single commission value read at line 1964 is applied to the **entire epoch's** (V2) or **entire block's** (V3) pool rewards, regardless of what commission was in effect for the majority of that period.

**Commission commitment enables upward changes**

Without a commitment, commission can only decrease. With an active `CommissionCommitment`, the staker may set commission to any value `<= max_commission` (and `!= old_commission`): [3](#0-2) 

This is the privileged path that makes upward commission changes possible.

---

### Impact Explanation

**Impact: High — Theft of unclaimed yield from delegators.**

For each epoch, the staker can extract up to `(max_commission − old_commission) / COMMISSION_DENOMINATOR × epoch_pool_rewards` in yield that rightfully belongs to delegators. With `max_commission = 50 %` and `old_commission = 0 %`, the staker can redirect half of every epoch's pool rewards to themselves. The stolen amount is transferred to the staker's `unclaimed_rewards_own` and is claimable via `claim_rewards`.

---

### Likelihood Explanation

**Likelihood: Medium.**

The attack requires the staker to have previously called `set_commission_commitment` with a `max_commission` above the current commission. This is a normal, documented protocol action available to any staker with a pool. Once the commitment is in place, the staker can repeat the attack every epoch for the commitment's lifetime (up to one year per the spec). The staker controls both the timing of `set_commission` and the timing of `attest` (via their operational address), so the two calls can be sequenced atomically within the same block.

---

### Recommendation

Before writing the new commission value in `update_commission`, invoke the reward-settlement path for the staker (analogous to the reported fix of calling `self_update` before updating `reward_config`). Concretely, trigger `_update_rewards` (or an equivalent internal settlement) for the staker so that all pool rewards accrued under the old commission are checkpointed into the pool's `cumulative_rewards_trace` before the commission changes.

---

### Proof of Concept

1. Staker stakes with `commission = 0` and calls `set_open_for_delegation`.
2. Staker calls `set_commission_commitment(max_commission: 5000, expiration_epoch: current + 10)`.
3. Delegators join the pool, attracted by 0 % commission.
4. One full epoch elapses; pool rewards accumulate.
5. The attestation window opens. **Before attesting**, the staker calls `set_commission(5000)` (50 %).
   - `update_commission` writes `commission = 5000` with no reward settlement.
6. The staker's operational address calls `attest`.
7. `update_rewards_from_attestation_contract` → `calculate_staker_pools_rewards` reads `commission = 5000` at line 1964 and applies it to the **entire epoch's** pool rewards.
8. `split_rewards_with_commission` routes 50 % of pool rewards to the staker as commission.
9. Delegators receive only 50 % of the rewards they earned during the epoch when commission was 0 %.
10. The staker repeats steps 5–9 every epoch until the commitment expires. [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L725-743)
```text
        fn set_commission(ref self: ContractState, commission: Commission) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(commission <= COMMISSION_DENOMINATOR, "{}", Error::COMMISSION_OUT_OF_RANGE);
            let staker_address = get_caller_address();
            let staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);

            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            if let Option::Some(old_commission) = staker_pool_info.commission.read() {
                self
                    .update_commission(
                        :staker_address, :staker_pool_info, :old_commission, :commission,
                    );
            } else {
                staker_pool_info.commission.write(Option::Some(commission));
                self.emit(Events::CommissionInitialized { staker_address, commission });
            }
        }
```

**File:** src/staking/staking.cairo (L1573-1609)
```text
        fn update_commission(
            ref self: ContractState,
            staker_address: ContractAddress,
            staker_pool_info: StoragePath<Mutable<InternalStakerPoolInfoV2>>,
            old_commission: Commission,
            commission: Commission,
        ) {
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

            // Emit event.
            self
                .emit(
                    Events::CommissionChanged {
                        staker_address, old_commission, new_commission: commission,
                    },
                );
        }
```

**File:** src/staking/staking.cairo (L1949-1991)
```text
        fn calculate_staker_pools_rewards(
            self: @ContractState,
            staker_address: ContractAddress,
            staker_pool_info: StoragePath<InternalStakerPoolInfoV2>,
            strk_total_rewards: Amount,
            strk_total_stake: NormalizedAmount,
            btc_total_rewards: Amount,
            btc_total_stake: NormalizedAmount,
            curr_epoch: Epoch,
        ) -> (Amount, Amount, Array<(ContractAddress, ContractAddress, NormalizedAmount, Amount)>) {
            // Array for rewards data needed to update pools.
            // Contains tuples of (pool_contract, token_address, pool_balance, pool_rewards).
            let mut pool_rewards_array = array![];
            let mut total_commission_rewards: Amount = Zero::zero();
            let mut total_pools_rewards: Amount = Zero::zero();
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
