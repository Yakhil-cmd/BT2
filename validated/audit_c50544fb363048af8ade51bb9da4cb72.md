### Title
Staker Can Instantly Raise Commission to 100% via `set_commission_commitment` + `set_commission`, Stealing Delegator Yield During Mandatory Exit Window - (File: src/staking/staking.cairo)

### Summary
A staker who operates a delegation pool can use the `set_commission_commitment` + `set_commission` two-step mechanism to instantaneously raise their commission from 0% to 100% (10000/10000). Because delegators must wait through the mandatory `exit_wait_window` before they can withdraw, all rewards accrued during that window are diverted entirely to the staker. The developers themselves acknowledge this in a code comment: *"Current commission increase safeguards still allow for sudden commission changes."*

### Finding Description

The `set_commission_commitment` function in `staking.cairo` allows a staker to set a `max_commission` ceiling up to `COMMISSION_DENOMINATOR` (10000 = 100%), provided `current_commission <= max_commission`:

```
assert!(current_commission <= max_commission, "{}", Error::MAX_COMMISSION_TOO_LOW);
```

Once the commitment is active (`current_epoch < expiration_epoch`), `set_commission` permits setting commission to any value up to `max_commission`, including the maximum:

```
if self.is_commission_commitment_active(:commission_commitment) {
    assert!(
        commission <= commission_commitment.max_commission,
        "{}",
        Error::INVALID_COMMISSION_WITH_COMMITMENT,
    );
    assert!(commission != old_commission, "{}", Error::INVALID_SAME_COMMISSION);
}
```

Both calls can be made in the same transaction or block. The commission change is **instantaneous** — it takes effect for the very next attestation reward distribution. Delegators have no on-chain mechanism to react before the change is applied.

The code comment at line 745–746 explicitly acknowledges the gap:

> `/// **Note**: Current commission increase safeguards still allow for sudden commission changes.`

### Impact Explanation

**High — Theft of unclaimed yield.**

After the commission is raised to 100%, every subsequent attestation reward is entirely routed to the staker's reward address. Delegators are forced to call `delegator_exit_intent` and then wait through the full `exit_wait_window` before they can call `delegator_exit_action`. All rewards generated during that window are stolen. The delegated principal is returned, but the yield earned during the exit window is permanently diverted to the malicious staker.

### Likelihood Explanation

**Medium-High.** Any staker who opens a delegation pool can execute this attack with no special access. The attack is profitable whenever the delegated pool balance is large enough that the stolen yield during the exit window exceeds the staker's own opportunity cost. A rational attacker would attract delegators with a 0% commission, wait for the pool to grow, then execute the two-step raise in a single epoch.

### Recommendation

1. **Short term**: Enforce a minimum delay (e.g., one full epoch) between when a commission increase is committed and when it can be applied. Delegators should be able to observe the pending increase and exit before it takes effect.
2. **Long term**: Emit a `CommissionIncreaseScheduled` event when a commitment is set with `max_commission > current_commission`, and only allow the increase to be applied starting from `expiration_epoch - 1` or later, giving delegators at least one epoch to react.

### Proof of Concept

```
// Step 1: Staker creates pool with commission = 0
system.stake(staker, amount, pool_enabled: true, commission: 0);
let pool = system.staking.get_pool(staker);

// Step 2: Delegators join, attracted by 0% commission
system.delegate(delegator, pool, amount: delegated_amount);
system.advance_k_epochs_and_attest(staker); // delegators earn rewards at 0%

// Step 3: Staker sets commitment allowing commission up to 100%
let current_epoch = system.staking.get_current_epoch();
// current_commission (0) <= max_commission (10000) — passes
system.staking.set_commission_commitment(
    max_commission: 10000,
    expiration_epoch: current_epoch + 1
);

// Step 4: Staker immediately raises commission to 100% in same epoch
// commission (10000) <= commitment.max_commission (10000) — passes
// commission (10000) != old_commission (0) — passes
system.staking.set_commission(commission: 10000);

// Step 5: Next attestation — 100% of pool rewards go to staker
system.advance_k_epochs_and_attest(staker);
// pool balance does NOT increase; all rewards go to staker.reward_address

// Step 6: Delegators can only exit after exit_wait_window
system.delegator_exit_intent(delegator, pool, amount: delegated_amount);
system.advance_time(time: system.staking.get_exit_wait_window());
// During this entire window, every attestation steals delegator yield
system.delegator_exit_action(delegator, pool);
// Delegator recovers principal but loses all yield earned during exit window
```

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L745-747)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
        /// **Note**: Updating epoch info can impact the commission commitment expiration date.
```

**File:** src/staking/staking.cairo (L768-778)
```text
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

**File:** src/staking/staking.cairo (L2178-2182)
```text
        fn is_commission_commitment_active(
            self: @ContractState, commission_commitment: CommissionCommitment,
        ) -> bool {
            self.get_current_epoch() < commission_commitment.expiration_epoch
        }
```
