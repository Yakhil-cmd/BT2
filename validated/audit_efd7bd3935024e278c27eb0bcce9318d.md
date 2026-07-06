### Title
Commission Commitment Minimum Duration of 1 Epoch Allows Staker to Instantly Raise Commission to 100% — (File: `src/staking/staking.cairo`)

---

### Summary

The `set_commission_commitment` function enforces only that `expiration_epoch > current_epoch` — a minimum of exactly 1 epoch. Because the commitment mechanism is the **only** path by which a staker can increase commission (without a commitment, commission can only decrease), a malicious staker can set a commitment with `max_commission = 10000` (100%) expiring in 1 epoch, immediately raise commission to 100%, and steal all delegator yield for at least one full exit-wait-window period before delegators can withdraw.

---

### Finding Description

`set_commission_commitment` in `src/staking/staking.cairo` validates the expiration epoch with only two bounds:

```cairo
assert!(expiration_epoch > current_epoch, "{}", Error::EXPIRATION_EPOCH_TOO_EARLY);
assert!(
    expiration_epoch - current_epoch <= self.get_epoch_info().epochs_in_year(),
    "{}",
    Error::EXPIRATION_EPOCH_TOO_FAR,
);
``` [1](#0-0) 

The lower bound is `expiration_epoch >= current_epoch + 1` — a single epoch. There is no meaningful minimum duration.

The `update_commission` internal function enforces the following logic:

- **No commitment present**: commission can only decrease.
- **Active commitment**: commission can be set to any value `<= max_commission` (increase allowed).
- **Expired commitment**: commission can only decrease. [2](#0-1) 

This means the commitment is the **sole mechanism** enabling a commission increase. A staker can exploit the 1-epoch minimum to:

1. Call `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)`.
2. In the same transaction or the next block, call `set_commission(10000)` — raising commission to 100%.
3. The commitment expires after 1 epoch, but delegators are locked in for at least `exit_wait_window` (default: 1 week) before they can withdraw. [3](#0-2) 

The `max_commission` is bounded only by `COMMISSION_DENOMINATOR`:

```cairo
assert!(max_commission <= COMMISSION_DENOMINATOR, "{}", Error::COMMISSION_OUT_OF_RANGE);
``` [4](#0-3) 

`COMMISSION_DENOMINATOR = 10000` (100%). [5](#0-4) 

---

### Impact Explanation

Delegators who entered the pool when commission was low (e.g., 5%) cannot exit before the `exit_wait_window` elapses (default 1 week). During this window, 100% of their earned rewards are taken as commission. This constitutes **theft of unclaimed yield** — a High-severity impact under the allowed scope.

---

### Likelihood Explanation

Any staker who has opened a delegation pool and set a commission is eligible to call `set_commission_commitment`. No privileged role is required. The call is permissionless for the staker. A rational attacker would execute this at the start of an epoch to maximize the number of reward-bearing blocks captured at 100% commission before delegators can react.

---

### Recommendation

Enforce a meaningful minimum commitment duration. For example, require the commitment to span at least `K` epochs (the consensus delay constant) or a protocol-defined minimum number of epochs (e.g., `epochs_in_year / 12` ≈ 1 month):

```cairo
assert!(
    expiration_epoch - current_epoch >= MIN_COMMITMENT_DURATION,
    "{}",
    Error::EXPIRATION_EPOCH_TOO_EARLY,
);
```

This mirrors the fix applied in the referenced Putty Finance report, which added a 15-minute minimum order duration.

---

### Proof of Concept

1. Staker `A` has operated with `commission = 500` (5%) and has accumulated delegators.
2. Staker `A` calls `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)`.
   - Passes: `10000 <= COMMISSION_DENOMINATOR` ✓
   - Passes: `500 <= 10000` (current_commission <= max_commission) ✓
   - Passes: `current_epoch + 1 > current_epoch` ✓ [6](#0-5) 
3. Staker `A` immediately calls `set_commission(10000)`.
   - `update_commission` sees an active commitment, checks `10000 <= 10000` ✓ and `10000 != 500` ✓ — commission is set to 100%. [7](#0-6) 
4. Delegators call `exit_delegation_pool_intent` but must wait `exit_wait_window` (1 week) before funds are released. [8](#0-7) 
5. During the entire exit window, all delegator rewards are consumed by the 100% commission. Delegators receive zero yield.
6. After 1 epoch the commitment expires; staker is now stuck at 100% commission (can only decrease), but the yield theft has already occurred.

### Citations

**File:** src/staking/staking.cairo (L73-73)
```text
    pub const COMMISSION_DENOMINATOR: Commission = 10000;
```

**File:** src/staking/staking.cairo (L74-75)
```text
    pub(crate) const DEFAULT_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: WEEK };
    pub(crate) const MAX_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: 12 * WEEK };
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

**File:** src/pool/pool.cairo (L256-293)
```text
        fn exit_delegation_pool_intent(ref self: ContractState, amount: Amount) {
            // Asserts.
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let old_delegated_stake = self.get_last_member_balance(:pool_member);
            let total_amount = old_delegated_stake + pool_member_info.unpool_amount;
            assert!(amount <= total_amount, "{}", GenericError::AMOUNT_TOO_HIGH);

            // Notify the staking contract of the removal intent.
            let unpool_time = self.undelegate_from_staking_contract_intent(:pool_member, :amount);

            // Edit the pool member to reflect the removal intent, and write to storage.
            if amount.is_zero() {
                pool_member_info.unpool_time = Option::None;
            } else {
                pool_member_info.unpool_time = Option::Some(unpool_time);
            }
            pool_member_info.unpool_amount = amount;
            let new_delegated_stake = total_amount - amount;
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Update the pool member's balance checkpoint.
            self.set_member_balance(:pool_member, amount: new_delegated_stake);

            // Emit events.
            self
                .emit(
                    Events::PoolMemberExitIntent {
                        pool_member, exit_timestamp: unpool_time, amount,
                    },
                );
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake, new_delegated_stake,
                    },
                );
        }
```
