### Title
Staker Can Atomically Raise Commission to Maximum via `set_commission_commitment` + `set_commission` With No Delegator Grace Period — (File: `src/staking/staking.cairo`)

---

### Summary

A staker can call `set_commission_commitment(max_commission=10000, expiration_epoch=current_epoch+1)` and then immediately call `set_commission(10000)` in the same block, raising commission from any value to 100% with zero advance notice to delegators. Delegators are then trapped for the full exit wait window (default 1 week, up to 12 weeks) during which all their yield is redirected to the staker.

---

### Finding Description

The `set_commission_commitment` function in `src/staking/staking.cairo` allows a staker to set a commitment that unlocks the ability to raise commission up to `max_commission`. The commitment becomes active **immediately** upon creation because `is_commission_commitment_active` only checks `current_epoch < expiration_epoch`, and the minimum valid `expiration_epoch` is `current_epoch + 1`. [1](#0-0) 

There is no enforced delay between setting the commitment and invoking `set_commission` to raise the commission. The code itself acknowledges this gap: [2](#0-1) 

**Attack path:**

1. Staker calls `set_commission_commitment(max_commission=10000, expiration_epoch=current_epoch+1)` — commitment is immediately active.
2. In the same block, staker calls `set_commission(10000)` — commission jumps to 100%.
3. `update_commission` at line 1583–1589 permits this because the commitment is active and `10000 <= max_commission`. [3](#0-2) 

4. `calculate_staker_pools_rewards` reads `commission = 10000` at line 1964, so `split_rewards_with_commission` routes 100% of delegation rewards to the staker. [4](#0-3) 

5. Delegators must call `exit_delegation_pool_intent` and wait the full `exit_wait_window` (default `WEEK`, max `12 * WEEK`) before recovering their principal — all yield during this window is stolen. [5](#0-4) [6](#0-5) 

---

### Impact Explanation

All delegation rewards accrued from the moment of the commission change until delegators complete their exit are redirected to the staker. This constitutes **theft of unclaimed yield** (High severity). With a large delegation pool and a 1-week exit window, the stolen yield is proportional to the total delegated stake and the protocol's inflation rate. The staker's own principal is not at risk; only delegator yield is affected.

---

### Likelihood Explanation

Any staker with an active delegation pool can execute this in two sequential transactions within the same block. There is a clear profit motive. The only prerequisite is having a pool with delegators, which is the normal operating state for any validator staker. No special privileges, leaked keys, or external dependencies are required.

---

### Recommendation

Enforce a minimum activation delay for the commission commitment before it can be used to **raise** commission. Specifically, `set_commission` should only be permitted to raise commission if the commitment was set at least `N` epochs ago (e.g., `N = 1` or `N = K`). This gives delegators a guaranteed observation window to exit before any commission increase takes effect. Concretely, store the epoch in which the commitment was created and add an assertion in `update_commission`:

```rust
assert!(
    current_epoch >= commission_commitment.created_epoch + MIN_COMMITMENT_DELAY,
    "{}",
    Error::COMMISSION_COMMITMENT_NOT_YET_ACTIVE,
);
```

---

### Proof of Concept

```
// Staker has commission = 500 (5%), delegators have staked significant STRK/BTC.

// Step 1: Set commitment with max_commission = 10000, active immediately.
staking.set_commission_commitment(
    max_commission: 10000,
    expiration_epoch: staking.get_current_epoch() + 1
);

// Step 2: Immediately raise commission to 100% in the same block.
staking.set_commission(commission: 10000);

// Result:
// - calculate_staker_pools_rewards now reads commission = 10000.
// - split_rewards_with_commission sends 100% of pool rewards to staker.
// - Delegators are locked for exit_wait_window (≥ 1 week) before they can exit.
// - All yield generated during that window is stolen by the staker.
```

### Citations

**File:** src/staking/staking.cairo (L74-75)
```text
    pub(crate) const DEFAULT_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: WEEK };
    pub(crate) const MAX_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: 12 * WEEK };
```

**File:** src/staking/staking.cairo (L745-746)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
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

**File:** src/pool/pool.cairo (L300-303)
```text
            let unpool_time = pool_member_info
                .unpool_time
                .expect_with_err(GenericError::MISSING_UNDELEGATE_INTENT);
            assert!(Time::now() >= unpool_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);
```
