### Title
Staker Can Instantly Raise Commission to 100% via `set_commission_commitment`, Stealing All Delegator Yield - (File: src/staking/staking.cairo)

### Summary
A staker can atomically set a `CommissionCommitment` with `max_commission = 10000` (100%) and then immediately call `set_commission(10000)` in the same block. Because an active commitment unlocks upward commission changes up to `max_commission` with no time-lock or advance-notice delay, a staker who initially advertised a low commission can instantly redirect 100% of pool rewards to themselves, leaving delegators with zero yield.

### Finding Description
`set_commission_commitment` requires only that `max_commission >= current_commission`: [1](#0-0) 

There is no delay between setting the commitment and being able to use it. Once an active commitment exists, `update_commission` permits any commission value up to `max_commission`, including a large increase: [2](#0-1) 

The code itself acknowledges this gap with a developer note: [3](#0-2) 

Without a commitment, `set_commission` only allows decreases: [4](#0-3) 

But the commitment path removes that protection entirely for the duration of the commitment window.

### Impact Explanation
A staker who has attracted delegators with a low commission (e.g., 2%) can:

1. Call `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)` — valid because `200 <= 10000`.
2. Immediately call `set_commission(10000)` — valid because `10000 <= max_commission` and `10000 != 200`.

From that point forward, 100% of pool rewards flow to the staker's reward address and 0% to the pool contract. Delegators who cannot exit within the same block (they must wait for `exit_wait_window` after `exit_intent`) lose all yield accrued during the elevated-commission period. This matches the **High** impact category: **Theft of unclaimed yield**.

### Likelihood Explanation
The attack requires only two sequential transactions from the staker's own address — no privileged role, no external dependency, no bridge interaction. Any staker who has opened a delegation pool can execute this. The only cost is the gas for two calls. Delegators have no on-chain mechanism to react before the commission change takes effect, and the mandatory exit window prevents them from withdrawing principal immediately.

### Recommendation
Enforce a minimum notice period before a commission increase takes effect. Concretely:

- Store the *pending* new commission alongside the epoch at which it was requested.
- Only apply the increase after at least one full epoch has elapsed, giving delegators time to observe the `CommissionChanged` event and submit `exit_intent` before the higher rate applies.
- Alternatively, prohibit commission increases entirely (only allow decreases or lateral moves within a pre-announced commitment), which is the spirit of the existing no-commitment path.

### Proof of Concept
```
// Staker has commission = 200 (2%), pool has delegators.

// Step 1 — set commitment with max = 100% (same tx or next block)
staking.set_commission_commitment(
    max_commission: 10000,
    expiration_epoch: current_epoch + 1,   // minimum valid value
);

// Step 2 — immediately raise to 100%
staking.set_commission(commission: 10000);

// Result: update_commission passes because:
//   commission (10000) <= commitment.max_commission (10000)  ✓
//   commission (10000) != old_commission (200)               ✓
// All future pool rewards go to staker; delegators earn 0.
```

Delegators cannot exit before the change takes effect because `exit_intent` starts a mandatory `exit_wait_window` timer, and the commission change is already live. [5](#0-4) [6](#0-5) [7](#0-6)

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
