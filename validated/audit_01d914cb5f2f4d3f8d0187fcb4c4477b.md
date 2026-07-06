### Title
Staker Can Instantly Raise Commission to Any Value via `set_commission_commitment` — (`File: src/staking/staking.cairo`)

---

### Summary

A staker can attract delegators with a low commission, then use `set_commission_commitment` + `set_commission` in two back-to-back transactions to instantly raise commission to 100%, draining all delegator yield for the duration of the exit wait window.

---

### Finding Description

Without a commitment, `set_commission` enforces a strict decrease-only rule: [1](#0-0) 

However, when a commission commitment is active, the only constraint is that the new commission does not exceed `max_commission` and is not equal to the old commission: [2](#0-1) 

The staker fully controls `max_commission` when calling `set_commission_commitment`. There is no cap on `max_commission` other than `COMMISSION_DENOMINATOR` (10000 = 100%): [3](#0-2) 

The only temporal constraint is that `expiration_epoch > current_epoch`, meaning a commitment valid for just one epoch is sufficient: [4](#0-3) 

The developers themselves acknowledge this gap with an explicit code comment: [5](#0-4) 

**Attack sequence (2 transactions, same block):**

1. Staker operates with a low commission (e.g., 1%) to attract delegators.
2. Staker calls `set_commission_commitment(max_commission=10000, expiration_epoch=current_epoch+1)`.
3. Staker immediately calls `set_commission(commission=10000)`.
4. Commission is now 100%. Delegators receive zero yield.
5. Delegators must wait through the exit wait window before they can exit.

---

### Impact Explanation

**High — Theft of unclaimed yield.**

All delegator rewards accrued during the exit wait window are redirected to the staker at 100% commission. The exit wait window is at minimum `DEFAULT_EXIT_WAIT_WINDOW` (1 week) and can be up to `MAX_EXIT_WAIT_WINDOW` (12 weeks): [6](#0-5) 

During this entire window, delegators earn zero yield while the staker captures 100% of all block rewards attributed to the pool.

---

### Likelihood Explanation

**High.** The attack requires no privileged access, no leaked keys, and no external dependencies. Any registered staker with a pool can execute it in two sequential transactions. The `set_commission_commitment` entry point is publicly callable by the staker address. The only prerequisite is having delegators in the pool, which is the normal operating state for any validator seeking to profit.

---

### Recommendation

1. **Enforce a delay between setting a commitment and being allowed to increase commission.** For example, require that the commitment was set at least `N` epochs before `set_commission` can raise the rate.
2. **Cap `max_commission` increases relative to the current commission** (e.g., no more than X% increase per epoch).
3. **Alternatively**, require that any commission increase only takes effect after a full exit wait window has elapsed, giving delegators time to exit before the new rate applies.

---

### Proof of Concept

```
Epoch E:
  tx1: staker.set_commission_commitment(max_commission=10000, expiration_epoch=E+1)
       // Passes: 10000 <= COMMISSION_DENOMINATOR, current_commission(100) <= 10000, E+1 > E
  tx2: staker.set_commission(commission=10000)
       // Passes: active commitment exists, 10000 <= 10000, 10000 != 100

Result: commission = 100% immediately.
Delegators call exit_intent but must wait DEFAULT_EXIT_WAIT_WINDOW (1 week) to 12 weeks.
All rewards during that window flow entirely to the staker.
```

Root cause: `update_commission` in `src/staking/staking.cairo` lines 1580–1597 imposes no delay or rate-limit on commission increases when a commitment is active, and `set_commission_commitment` in lines 748–785 places no ceiling on `max_commission` beyond the protocol maximum of 10000. [2](#0-1) [7](#0-6)

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
