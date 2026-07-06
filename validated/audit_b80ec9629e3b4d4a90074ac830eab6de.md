### Title
Staker Can Instantly Raise Commission to Maximum via `set_commission_commitment` + `set_commission` With No Delay, Stealing Delegator Yield - (File: `src/staking/staking.cairo`)

---

### Summary

A staker can atomically set a `CommissionCommitment` with `max_commission = 10000` (100%) and immediately call `set_commission` to raise the commission to 100% in the same block. There is no mandatory time window between the two calls. Delegators have no opportunity to exit before the new commission rate is applied to the next attestation reward, causing all pool rewards to be redirected to the staker.

---

### Finding Description

The `set_commission_commitment` function allows any staker with a pool to publish a commitment that permits raising commission up to `max_commission` until `expiration_epoch`. The only constraints are that `max_commission >= current_commission`, `expiration_epoch > current_epoch`, and no active commitment already exists. [1](#0-0) 

Once a commitment is active, `set_commission` permits raising the commission to any value `<= max_commission` immediately, with no enforced delay: [2](#0-1) 

The commission change takes effect immediately for the next `update_rewards_from_attestation_contract` call. The codebase itself acknowledges this gap with an inline note: [3](#0-2) 

The interface documentation for `set_exit_wait_window` notes that exit-intent holders are protected from retroactive window changes, but no equivalent protection exists for commission increases: [4](#0-3) 

---

### Impact Explanation

**High — Theft of unclaimed yield.**

A malicious staker can execute the following in two consecutive transactions (or even the same block):

1. `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)`
2. `set_commission(commission: 10000)`

The commission is now 100%. When the staker attests in the current epoch, `split_rewards_with_commission` routes 100% of pool rewards to the staker and 0% to the pool. All delegators who earned yield in that epoch receive nothing. Their accrued-but-not-yet-distributed rewards are permanently redirected to the staker.

---

### Likelihood Explanation

**Medium.** Any staker who has opened a delegation pool can execute this attack. No privileged role, leaked key, or external dependency is required — only the staker's own address. The attack is profitable whenever the pool holds meaningful delegated stake. The two-step sequence (`set_commission_commitment` then `set_commission`) is callable by any staker address in back-to-back transactions within the same epoch.

---

### Recommendation

Enforce a mandatory delay between the time a `CommissionCommitment` is set and the earliest epoch at which the commission may be raised. For example, require that `set_commission` with an upward change can only execute at least `K` epochs after the commitment was recorded. This mirrors the K-delay already used for staking-power changes and gives delegators a predictable window to observe the pending increase and exit via `exit_delegation_pool_intent` before it takes effect.

---

### Proof of Concept

```
// Epoch N, staker has commission = 0%, pool has delegators.

// Step 1 — staker sets commitment allowing 100% commission, expiring next epoch.
staking.set_commission_commitment(
    max_commission: 10000,
    expiration_epoch: current_epoch + 1   // minimum allowed value
);

// Step 2 — staker immediately raises commission to 100% (same block).
staking.set_commission(commission: 10000);

// Step 3 — staker attests in epoch N.
// split_rewards_with_commission routes 100% of pool rewards to staker.
// Delegators receive 0 rewards for epoch N.
// All delegator yield for epoch N is permanently stolen.
```

Delegators have no on-chain mechanism to detect and react to steps 1–2 before step 3 executes, because there is no enforced epoch gap between the commitment and the commission raise.

### Citations

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

**File:** src/staking/staking.cairo (L1580-1600)
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

            // Update commission in storage.
            staker_pool_info.commission.write(Option::Some(commission));
```

**File:** src/staking/interface.cairo (L247-251)
```text
    /// Note: Changing the exit wait window does not retroactively affect validators/delegators
    /// who already submitted an exit_intent call. They remain governed by
    /// the old exit wait window when calling exit_action.
    /// Note: The exit wait window must be at least K epochs.
    fn set_exit_wait_window(ref self: TContractState, exit_wait_window: TimeDelta);
```
