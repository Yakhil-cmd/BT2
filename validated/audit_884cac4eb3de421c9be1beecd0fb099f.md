### Title
Staker Can Instantly Raise Commission to 100% via Commission Commitment, Stealing Delegator Yield - (File: src/staking/staking.cairo)

### Summary

The `set_commission_commitment` + `set_commission` flow in `src/staking/staking.cairo` allows a staker to attract delegators with a low commission rate and then instantly raise commission to 100% in a single epoch, stealing all delegator yield during the mandatory exit window.

### Finding Description

The `update_commission` internal function, called by `set_commission`, applies the following logic when a commission commitment is active:

```
if self.is_commission_commitment_active(:commission_commitment) {
    assert!(
        commission <= commission_commitment.max_commission,
        "{}",
        Error::INVALID_COMMISSION_WITH_COMMITMENT,
    );
    assert!(commission != old_commission, "{}", Error::INVALID_SAME_COMMISSION);
}
``` [1](#0-0) 

When a commitment is active, the only constraints are: (1) the new commission must not exceed `max_commission`, and (2) it must differ from the current commission. There is **no lower-bound constraint** — the commission can be raised to any value up to `max_commission`, including 10000 (100%).

The `set_commission_commitment` function requires only that `current_commission <= max_commission`: [2](#0-1) 

A staker can therefore:
1. Operate with commission = 100 (1%) to attract delegators.
2. Call `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)` — this passes because `100 <= 10000`.
3. Immediately call `set_commission(10000)` in the same epoch — this passes because `10000 <= 10000` and `10000 != 100`.
4. Commission is now 100%. All subsequent reward distributions send 0% to delegators.

The codebase itself acknowledges this gap with a comment directly above `set_commission_commitment`: [3](#0-2) 

The `is_commission_commitment_active` check confirms the commitment is active for the entire current epoch when `expiration_epoch = current_epoch + 1`: [4](#0-3) 

Delegators who call `exit_delegation_pool_intent` must wait for `DEFAULT_EXIT_WAIT_WINDOW` (1 week) before recovering their principal: [5](#0-4) 

During that week, the staker attests and collects 100% of all pool rewards, with delegators receiving nothing.

### Impact Explanation

**High — Theft of unclaimed yield.** Delegators who joined a pool expecting a 1% commission rate have their entire yield stolen for the duration of the exit window. The staker receives 100% of rewards that should have been split with delegators. This is a direct, quantifiable loss of yield for every delegator in the pool.

### Likelihood Explanation

**High.** Any registered staker with an active delegation pool can execute this attack with two sequential transactions in the same epoch. No special privileges, leaked keys, or external dependencies are required. The attack is cheap to execute and profitable for the staker proportional to the total delegated stake in their pool.

### Recommendation

1. **Disallow commission increases entirely.** Remove the ability to raise commission above the current value even when a commitment is active. The commitment's purpose should be to cap future decreases, not to enable increases.
2. **Enforce a delay on commission increases.** If increases are intentional, require the new commission to take effect only after `K` epochs (matching the balance trace delay), giving delegators time to exit before the higher rate applies.
3. **Notify delegators on-chain with a time-lock.** Emit a pending commission change event and only apply it after a minimum notice period (e.g., one full epoch).

### Proof of Concept

1. Staker S deploys a pool with `commission = 100` (1%).
2. Delegators D1, D2, D3 call `enter_delegation_pool` attracted by the 1% rate.
3. S calls `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)`.
   - Passes: `current_commission (100) <= max_commission (10000)`. ✓
4. S immediately calls `set_commission(10000)`.
   - Passes: `10000 <= 10000` and `10000 != 100`. ✓
   - Commission is now 100%.
5. S attests within the attestation window. `update_rewards_from_attestation_contract` is called. The `split_rewards_with_commission` function distributes 100% to S and 0% to the pool.
6. D1, D2, D3 call `exit_delegation_pool_intent`. They must wait `DEFAULT_EXIT_WAIT_WINDOW = 1 week`.
7. During that week, S continues attesting and collecting 100% of all rewards. Delegators earn nothing.
8. After 1 week, delegators recover only their principal — all accrued yield during the exit window is permanently lost to them and captured by S.

### Citations

**File:** src/staking/staking.cairo (L74-74)
```text
    pub(crate) const DEFAULT_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: WEEK };
```

**File:** src/staking/staking.cairo (L745-747)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
        /// **Note**: Updating epoch info can impact the commission commitment expiration date.
```

**File:** src/staking/staking.cairo (L769-778)
```text
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
```

**File:** src/staking/staking.cairo (L1583-1589)
```text
                if self.is_commission_commitment_active(:commission_commitment) {
                    assert!(
                        commission <= commission_commitment.max_commission,
                        "{}",
                        Error::INVALID_COMMISSION_WITH_COMMITMENT,
                    );
                    assert!(commission != old_commission, "{}", Error::INVALID_SAME_COMMISSION);
```

**File:** src/staking/staking.cairo (L2178-2182)
```text
        fn is_commission_commitment_active(
            self: @ContractState, commission_commitment: CommissionCommitment,
        ) -> bool {
            self.get_current_epoch() < commission_commitment.expiration_epoch
        }
```
