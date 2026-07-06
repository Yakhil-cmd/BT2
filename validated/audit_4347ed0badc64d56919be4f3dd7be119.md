### Title
Commission Can Be Increased Mid-Epoch via Commitment, Immediately Stealing Delegator Yield - (File: src/staking/staking.cairo)

### Summary

A staker can atomically call `set_commission_commitment` followed by `set_commission` to raise their commission to up to 100% within the same epoch, with no delay. Because commission is read at attestation time from live storage, the new rate applies to the **current** epoch's rewards, redirecting delegator yield to the staker before delegators can react.

### Finding Description

The `set_commission_commitment` function allows a staker to set a `CommissionCommitment` with any `max_commission` up to `COMMISSION_DENOMINATOR` (10000 = 100%), provided `max_commission >= current_commission` and `expiration_epoch > current_epoch`. [1](#0-0) 

The commitment becomes **immediately active** upon writing, because `is_commission_commitment_active` simply checks `current_epoch < expiration_epoch`: [2](#0-1) 

With an active commitment, `update_commission` allows the commission to be set to any value up to `max_commission` (including an increase): [3](#0-2) 

The new commission is written to storage immediately with no epoch delay. When rewards are calculated during attestation, `calculate_staker_pools_rewards` reads the commission from live storage at that moment: [4](#0-3) 

The developers themselves acknowledge this gap in a code comment directly above `set_commission_commitment`: [5](#0-4) 

### Impact Explanation

A staker who advertised 0% commission can, in the same block or epoch:
1. Call `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)`.
2. Immediately call `set_commission(10000)`.

All delegator rewards for the current epoch are then redirected to the staker as commission. Delegators cannot exit in time because `exit_wait_window` is at least K epochs. This constitutes **theft of unclaimed yield** (High severity).

### Likelihood Explanation

The attack requires only that the staker controls their own staker address — no privileged role, no leaked key, no external dependency. It can be executed atomically in two transactions (or even one multicall). The attack is repeatable: after the commitment expires the staker can lower commission to attract new delegators, then repeat the cycle.

### Recommendation

1. **Delay commission increases**: Apply any commission increase only starting from the **next** epoch, not the current one. Commission decreases can remain immediate (they benefit delegators).
2. **Enforce a minimum notice period**: Require that `expiration_epoch >= current_epoch + K` so delegators have at least K epochs to observe the commitment and exit before it can be exercised.
3. **Separate commitment activation from immediate use**: Require at least one full epoch to elapse between setting a commitment and being permitted to increase commission under it.

### Proof of Concept

```
Epoch N, block B:
  staker.set_commission_commitment(max_commission=10000, expiration_epoch=N+1)
  // commitment is immediately active: current_epoch(N) < expiration_epoch(N+1)

  staker.set_commission(10000)
  // update_commission: commitment active → assert commission <= 10000 ✓
  // commission written to storage = 10000 (100%)

Epoch N, block B+1 (attestation window):
  attestation_contract → staking.update_rewards_from_attestation_contract(staker)
  // calculate_staker_pools_rewards reads commission = 10000
  // split_rewards_with_commission: all pool rewards go to staker as commission
  // delegators receive 0 yield for epoch N
``` [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** src/staking/staking.cairo (L745-747)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
        /// **Note**: Updating epoch info can impact the commission commitment expiration date.
```

**File:** src/staking/staking.cairo (L748-784)
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

**File:** src/staking/staking.cairo (L1949-2001)
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
                total_commission_rewards += commission_rewards;
                total_pools_rewards += pool_rewards;
                if pool_rewards.is_non_zero() {
                    pool_rewards_array
                        .append(
                            (pool_contract, token_address, pool_balance_curr_epoch, pool_rewards),
                        );
                }
            }
            (total_commission_rewards, total_pools_rewards, pool_rewards_array)
```

**File:** src/staking/staking.cairo (L2178-2182)
```text
        fn is_commission_commitment_active(
            self: @ContractState, commission_commitment: CommissionCommitment,
        ) -> bool {
            self.get_current_epoch() < commission_commitment.expiration_epoch
        }
```
