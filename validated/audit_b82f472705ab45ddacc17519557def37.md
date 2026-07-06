### Title
Staker Can Raise Commission Mid-Epoch and Apply It Retroactively to Delegators' Accumulated Rewards - (File: `src/staking/staking.cairo`)

---

### Summary

The `set_commission_commitment` + `set_commission` flow in `staking.cairo` allows a staker to raise their commission rate within the same epoch it was set, and because commission is read at attestation time (not at epoch-start), the higher rate is applied to rewards that delegators had already been earning throughout the epoch. This is the direct analog of the SablierFlow retroactive-fee bug: a parameter change applies to already-accumulated value.

---

### Finding Description

Commission is applied to pool rewards inside `calculate_staker_pools_rewards()`, which reads the **current** commission from storage at the moment of attestation:

```cairo
let commission = staker_pool_info.commission();
``` [1](#0-0) 

The commission is then immediately used to split the epoch's rewards between the staker and the pool:

```cairo
let (commission_rewards, pool_rewards) = split_rewards_with_commission(
    rewards_including_commission: pool_rewards_including_commission, :commission,
);
``` [2](#0-1) 

`set_commission` writes the new value directly to storage with no epoch delay:

```cairo
staker_pool_info.commission.write(Option::Some(commission));
``` [3](#0-2) 

Normally, commission can only be **decreased**. However, `set_commission_commitment` lets a staker pre-commit to a `max_commission` ceiling, after which `set_commission` may raise the rate up to that ceiling while the commitment is active:

```cairo
assert!(current_commission <= max_commission, "{}", Error::MAX_COMMISSION_TOO_LOW);
assert!(expiration_epoch > current_epoch, "{}", Error::EXPIRATION_EPOCH_TOO_EARLY);
``` [4](#0-3) 

The commitment becomes active immediately upon creation (the only constraint is `expiration_epoch > current_epoch`, meaning it can expire as soon as the next epoch). Within the same epoch the commitment is set, the staker can call `set_commission` to raise to `max_commission`:

```cairo
if self.is_commission_commitment_active(:commission_commitment) {
    assert!(
        commission <= commission_commitment.max_commission, ...
    );
    assert!(commission != old_commission, ...);
``` [5](#0-4) 

The developers themselves acknowledge this gap in a code comment:

> **Note**: Current commission increase safeguards still allow for sudden commission changes. [6](#0-5) 

---

### Impact Explanation

**High — Theft of unclaimed yield.**

A malicious staker can execute the following in a single epoch (even a single block):

1. Call `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)` — commitment is immediately active.
2. Call `set_commission(10000)` — commission raised to 100% in the same epoch.
3. Call `attest()` — rewards for the entire epoch are calculated with 100% commission; delegators receive **zero** pool rewards.

Delegators cannot protect themselves: the `exit_wait_window` prevents immediate exit, and the staker can attest in the same block as the commission raise. Rewards that delegators had been earning throughout the epoch (by having their stake active) are entirely captured by the staker.

The staker can repeat this pattern: lower commission back to 0% to attract new delegators, then rug again after the commitment expires and a new one is set.

---

### Likelihood Explanation

**Medium.** The attack requires a staker who is willing to act maliciously and sacrifice their reputation. However:
- The entry path is fully permissionless — any registered staker with a pool can execute it.
- No privileged role, leaked key, or external dependency is needed.
- The two-step setup (`set_commission_commitment` then `set_commission`) can be done atomically in the same block, giving delegators no reaction window.
- The `exit_wait_window` ensures delegators cannot exit before the staker attests.

---

### Recommendation

Apply a time-lock (at minimum one full epoch) between when a commission increase is committed and when it takes effect. Specifically, `set_commission` should not allow a commission increase to take effect until `current_epoch >= expiration_epoch` of the commitment, rather than immediately upon calling `set_commission`. This ensures delegators have at least one full epoch of advance notice to exit before the higher rate is applied.

Alternatively, store the commission rate that was in effect at the **start** of each epoch (similar to how balance traces work) and use that historical rate when calculating rewards for that epoch, rather than the rate at attestation time.

---

### Proof of Concept

```
Epoch N:
  staker.set_commission_commitment(max_commission=10000, expiration_epoch=N+1)
  // commitment is immediately active (current_epoch N < expiration_epoch N+1)

  staker.set_commission(10000)
  // allowed: commission(10000) <= max_commission(10000), commission != old_commission

  staker.attest()
  // calculate_staker_pools_rewards reads commission = 10000
  // split_rewards_with_commission: commission_rewards = 100% of pool rewards
  // pool receives 0 rewards
  // delegators who staked all of epoch N receive 0 yield

Epoch N+1:
  // commitment expired; staker lowers commission back to 0% to attract new delegators
  staker.set_commission(0)  // allowed: decrease without commitment

  // new delegators join...

Epoch N+2:
  // repeat attack
```

### Citations

**File:** src/staking/staking.cairo (L745-746)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
```

**File:** src/staking/staking.cairo (L770-771)
```text
            assert!(current_commission <= max_commission, "{}", Error::MAX_COMMISSION_TOO_LOW);
            assert!(expiration_epoch > current_epoch, "{}", Error::EXPIRATION_EPOCH_TOO_EARLY);
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

**File:** src/staking/staking.cairo (L1599-1600)
```text
            // Update commission in storage.
            staker_pool_info.commission.write(Option::Some(commission));
```

**File:** src/staking/staking.cairo (L1964-1964)
```text
            let commission = staker_pool_info.commission();
```

**File:** src/staking/staking.cairo (L1989-1991)
```text
                let (commission_rewards, pool_rewards) = split_rewards_with_commission(
                    rewards_including_commission: pool_rewards_including_commission, :commission,
                );
```
