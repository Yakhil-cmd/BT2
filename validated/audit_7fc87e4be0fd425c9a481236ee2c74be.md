### Title
Staker Can Instantly Raise Commission to 100% via Commitment Mechanism, Stealing Delegator Yield — (File: src/staking/staking.cairo)

---

### Summary

The `set_commission_commitment` + `set_commission` flow in `staking.cairo` allows any staker with an active delegation pool to increase their commission to the maximum value of 100% (`COMMISSION_DENOMINATOR = 10000`) within the same epoch, with no enforced delay for delegators to exit. Because the commission is read at reward-calculation time, delegators who earned yield during that epoch receive zero rewards.

---

### Finding Description

`COMMISSION_DENOMINATOR` is set to `10000` (100%), which is the only upper bound on commission. [1](#0-0) 

`set_commission` enforces only `commission <= COMMISSION_DENOMINATOR`: [2](#0-1) 

`set_commission_commitment` requires only `expiration_epoch > current_epoch`, meaning the minimum valid commitment is `expiration_epoch = current_epoch + 1`: [3](#0-2) 

`is_commission_commitment_active` returns `true` whenever `current_epoch < expiration_epoch`: [4](#0-3) 

Because the commitment is active immediately after being set (in the same epoch), the staker can call `set_commission(COMMISSION_DENOMINATOR)` in the very same epoch, jumping commission from e.g. 5% to 100% with no waiting period. The code itself acknowledges this gap: [5](#0-4) 

When rewards are calculated via `calculate_staker_pools_rewards`, the commission is read from storage at that moment: [6](#0-5) 

The `split_rewards_with_commission` utility then applies the new 100% commission, leaving delegators with zero pool rewards: [7](#0-6) 

---

### Impact Explanation

Delegators who staked under a low-commission pool (e.g., 5%) earn yield proportional to their balance throughout an epoch. If the staker raises commission to 100% before the attestation that triggers reward calculation, the entire pool reward is redirected to the staker as commission. Delegators receive zero yield for that epoch despite having contributed stake. This is **theft of unclaimed yield** (High impact).

---

### Likelihood Explanation

Any registered staker who has opened a delegation pool can execute this in two sequential transactions within the same epoch. No special privilege, leaked key, or external dependency is required. The only prerequisite is having at least one delegator in the pool, which is the normal operating condition for any active validator.

---

### Recommendation

1. **Short term**: Enforce a meaningful upper bound on commission that is strictly below 100% (e.g., 30–50%), analogous to how `set_exit_wait_window` enforces `exit_wait_window <= MAX_EXIT_WAIT_WINDOW`.
2. **Short term**: Require that a commission commitment must be set at least one full epoch before it can be acted upon (i.e., `expiration_epoch >= current_epoch + 2` and the increase only takes effect in the epoch after the commitment is set), giving delegators at least one epoch to observe the pending change and exit.
3. **Long term**: Consider making commission increases subject to a timelock or a minimum notice period, so delegators can exit before a higher commission applies to their rewards.

---

### Proof of Concept

```
Epoch N:
  1. Staker has pool with commission = 500 (5%), delegators have staked.
  2. Staker calls set_commission_commitment(max_commission: 10000, expiration_epoch: N+1).
     → Commitment is immediately active because current_epoch (N) < expiration_epoch (N+1).
  3. Staker calls set_commission(10000) in the same epoch N.
     → update_commission sees active commitment, allows increase to 10000.
  4. Staker's operational address calls attest() → triggers update_rewards.
     → calculate_staker_pools_rewards reads commission = 10000.
     → split_rewards_with_commission: commission_rewards = pool_rewards_including_commission * 10000 / 10000 = 100%.
     → pool_rewards = 0.
  5. Delegators claim_rewards → receive 0 STRK for epoch N.
     All yield for epoch N is transferred to the staker's reward address.
``` [8](#0-7) [9](#0-8)

### Citations

**File:** src/staking/staking.cairo (L73-73)
```text
    pub const COMMISSION_DENOMINATOR: Commission = 10000;
```

**File:** src/staking/staking.cairo (L725-742)
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
```

**File:** src/staking/staking.cairo (L745-746)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
```

**File:** src/staking/staking.cairo (L748-785)
```text
        fn set_commission_commitment(
            ref self: ContractState, max_commission: Commission, expiration_epoch: Epoch,
        ) {
            self.general_prerequisites();
            assert!(max_commission <= COMMISSION_DENOMINATOR, "{}", Error::COMMISSION_OUT_OF_RANGE);
            let staker_address = get_caller_address();
            let staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            assert!(staker_pool_info.has_pool(), "{}", Error::MISSING_POOL_CONTRACT);
            let current_epoch = self.get_current_epoch();
            if let Option::Some(commission_commitment) = staker_pool_info
                .commission_commitment
                .read() {
                assert!(
                    !self.is_commission_commitment_active(:commission_commitment),
                    "{}",
                    Error::COMMISSION_COMMITMENT_EXISTS,
                );
            }
            // Staker must have a commission since it has a pool.
            let current_commission = staker_pool_info.commission();
            assert!(current_commission <= max_commission, "{}", Error::MAX_COMMISSION_TOO_LOW);
            assert!(expiration_epoch > current_epoch, "{}", Error::EXPIRATION_EPOCH_TOO_EARLY);
            assert!(
                expiration_epoch - current_epoch <= self.get_epoch_info().epochs_in_year(),
                "{}",
                Error::EXPIRATION_EPOCH_TOO_FAR,
            );
            let commission_commitment = CommissionCommitment { max_commission, expiration_epoch };
            staker_pool_info.commission_commitment.write(Option::Some(commission_commitment));
            self
                .emit(
                    Events::CommissionCommitmentSet {
                        staker_address, max_commission, expiration_epoch,
                    },
                );
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

**File:** src/staking/staking.cairo (L2178-2182)
```text
        fn is_commission_commitment_active(
            self: @ContractState, commission_commitment: CommissionCommitment,
        ) -> bool {
            self.get_current_epoch() < commission_commitment.expiration_epoch
        }
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
