### Title
Staker Can Instantly Raise Commission to 100% via `set_commission_commitment`, Stealing Delegator Yield - (File: `src/staking/staking.cairo`)

### Summary

A staker can use `set_commission_commitment` followed immediately by `set_commission` to raise their commission to 100% in a single epoch, stealing all pool rewards from delegators who are locked in for the full `exit_wait_window`.

### Finding Description

The `set_commission_commitment` mechanism was designed to allow stakers to signal a bounded commission range to delegators. However, it also enables a staker to **increase** commission immediately — up to `max_commission` — within the same transaction block, with no epoch-based delay.

The attack path:

1. Staker operates a pool with a low commission (e.g., 0%) to attract delegators.
2. Staker calls `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)`.
3. In the same block (or immediately after), staker calls `set_commission(commission: 10000)`.
4. `update_commission` allows this because the commitment is active and `10000 <= max_commission`.
5. The new 100% commission is written to storage immediately.
6. On the next reward calculation (`update_rewards_from_attestation_contract` or `update_rewards`), `calculate_staker_pools_rewards` reads the **current** commission from storage and applies it to all pool rewards.
7. All pool rewards for that epoch flow to the staker as commission; delegators receive zero.
8. Delegators cannot exit before the `exit_wait_window` (default 1 week, up to 12 weeks) elapses.

The code comment at line 745–746 even acknowledges this: `/// **Note**: Current commission increase safeguards still allow for sudden commission changes.`

### Impact Explanation

**High — Theft of unclaimed yield from delegators.**

A malicious staker can drain 100% of pool rewards for at least one full epoch (and up to the commitment duration). Delegators who delegated expecting a low commission rate have their yield stolen and cannot exit before the `exit_wait_window` expires. The staker profits directly at the delegators' expense.

### Likelihood Explanation

**High.** Any staker who has opened a delegation pool can execute this attack with two sequential transactions. No special privileges, leaked keys, or external dependencies are required. The attack is most profitable after the staker has accumulated a large delegated pool balance.

### Recommendation

Apply commission increases with an epoch-based delay (analogous to how balance changes use `epoch + K`). Specifically:
- Store a `pending_commission` and `pending_commission_effective_epoch` alongside the current commission.
- When calculating rewards, use the commission that was effective at the reward epoch, not the current storage value.
- This gives delegators at least K epochs of advance notice to exit before a higher commission takes effect.

### Proof of Concept

**Root cause — commission is read at reward time, not at delegation time:** [1](#0-0) 

The `commission` variable is fetched from live storage at the moment rewards are split. There is no snapshot of the commission rate at the time each delegator joined.

**`set_commission_commitment` allows setting `max_commission` up to 10000 with minimum expiration of `current_epoch + 1`:** [2](#0-1) 

**`update_commission` permits raising commission to any value ≤ `max_commission` while the commitment is active:** [3](#0-2) 

**`is_commission_commitment_active` returns `true` as long as `current_epoch < expiration_epoch`, so the commitment is active immediately after being set:** [4](#0-3) 

**`set_commission` writes the new commission directly to storage with no delay:** [5](#0-4) 

**The protocol's own code comment acknowledges the gap:** [6](#0-5) 

**Attack sequence (concrete):**
```
// Step 1: Staker has commission = 0, large delegated pool
set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)

// Step 2: Immediately raise commission to 100%
set_commission(commission: 10000)

// Step 3: Attest / update_rewards is called — all pool rewards go to staker as commission
// Delegators receive 0 rewards for the epoch

// Step 4: Delegators call exit_delegation_pool_intent but must wait exit_wait_window (≥1 week)
// During this window, staker continues collecting 100% commission
```

### Citations

**File:** src/staking/staking.cairo (L745-747)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
        /// **Note**: Updating epoch info can impact the commission commitment expiration date.
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

**File:** src/staking/staking.cairo (L2178-2182)
```text
        fn is_commission_commitment_active(
            self: @ContractState, commission_commitment: CommissionCommitment,
        ) -> bool {
            self.get_current_epoch() < commission_commitment.expiration_epoch
        }
```
