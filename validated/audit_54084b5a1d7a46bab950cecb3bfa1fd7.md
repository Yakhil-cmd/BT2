### Title
Staker Can Instantly Raise Commission to 100% via Commitment, Stealing All Delegator Yield - (File: `src/staking/staking.cairo`)

---

### Summary

A staker with an existing delegation pool can call `set_commission_commitment` with `max_commission = COMMISSION_DENOMINATOR` (10000 = 100%) and then immediately call `set_commission(10000)` in the same block. This atomically raises the commission to 100%, routing all future pool rewards to the staker as commission and leaving delegators with zero yield. Delegators are trapped for the full `exit_wait_window` (default 1 week, up to 12 weeks) during which they earn nothing. The developers themselves acknowledge this in a code comment.

---

### Finding Description

Without a commitment, `update_commission` only allows commission to **decrease**: [1](#0-0) 

The commitment mechanism was introduced to allow controlled increases. However, `set_commission_commitment` places no upper bound on `max_commission` other than `COMMISSION_DENOMINATOR` (100%), and only requires `max_commission >= current_commission`: [2](#0-1) 

Once a commitment is active, `update_commission` allows the commission to be set to **any** value up to `max_commission`, with no delay and no minimum notice period for delegators: [3](#0-2) 

The developers explicitly acknowledge this gap in a comment directly above `set_commission_commitment`: [4](#0-3) 

When commission is 100%, `split_rewards_with_commission` returns `pool_rewards = 0` for every reward distribution: [5](#0-4) 

`COMMISSION_DENOMINATOR` is 10000: [6](#0-5) 

---

### Impact Explanation

**High — Theft of unclaimed yield.**

All pool rewards that would have accrued to delegators during the exit window are instead captured by the staker as commission. With a 1-week default exit window and a 12-week maximum, delegators lose a material fraction of their annual yield. The staker profits directly: every STRK that would have gone to the pool now goes to `staker_info.unclaimed_rewards_own` via the commission path. [7](#0-6) 

---

### Likelihood Explanation

**Medium-High.** The attack requires only two sequential transactions from the staker's own address — no privileged role, no external dependency, no leaked key. The staker has a direct financial incentive (capturing delegator yield). The only deterrent is reputational damage, which is irrelevant for an anonymous or short-lived staker. The minimum commitment expiration is `current_epoch + 1`, so the window to detect and exit before the raise takes effect is at most one epoch. [8](#0-7) 

---

### Recommendation

1. **Enforce a minimum delay between setting a commitment and the commission increase taking effect.** The new commission value should only become effective after at least `K` epochs, giving delegators time to observe the on-chain event and exit.
2. **Cap the maximum single-step commission increase** (e.g., no more than X basis points per epoch).
3. **Alternatively**, require that any `max_commission` set in a commitment must be announced at least `K` epochs before it can be used to raise the commission.

---

### Proof of Concept

```
// Precondition: staker has pool with commission = 0%, many delegators have joined.

// Step 1 — staker sets a commitment with max_commission = 10000 (100%)
//           expiration_epoch = current_epoch + 1 (minimum allowed)
staking.set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1);

// Step 2 — staker immediately raises commission to 100% in the same block
//           Passes because: commitment is active AND 10000 <= 10000 AND 10000 != 0
staking.set_commission(commission: 10000);

// Result: split_rewards_with_commission(rewards, 10000)
//   commission_rewards = rewards * 10000 / 10000 = rewards  → goes to staker
//   pool_rewards       = rewards - rewards        = 0        → delegators earn nothing

// Delegators must now call exit_delegation_pool_intent() and wait exit_wait_window
// (default 1 week, max 12 weeks) before recovering principal.
// All yield during that window is stolen by the staker.
``` [9](#0-8) [10](#0-9) [11](#0-10)

### Citations

**File:** src/staking/staking.cairo (L73-73)
```text
    pub const COMMISSION_DENOMINATOR: Commission = 10000;
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

**File:** src/staking/staking.cairo (L1989-1993)
```text
                let (commission_rewards, pool_rewards) = split_rewards_with_commission(
                    rewards_including_commission: pool_rewards_including_commission, :commission,
                );
                total_commission_rewards += commission_rewards;
                total_pools_rewards += pool_rewards;
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

**File:** src/staking/utils.cairo (L81-90)
```text
pub(crate) fn compute_commission_amount_rounded_down(
    rewards_including_commission: Amount, commission: Commission,
) -> Amount {
    mul_wide_and_div(
        lhs: rewards_including_commission,
        rhs: commission.into(),
        div: COMMISSION_DENOMINATOR.into(),
    )
        .expect_with_err(err: InternalError::COMMISSION_ISNT_AMOUNT_TYPE)
}
```
