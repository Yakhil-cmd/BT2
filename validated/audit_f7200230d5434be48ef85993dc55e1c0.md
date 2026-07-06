### Title
Staker Can Instantly Raise Commission to Maximum via `set_commission_commitment` + `set_commission` in the Same Block, Stealing Delegator Yield - (File: src/staking/staking.cairo)

### Summary

A staker can call `set_commission_commitment` and immediately follow it with `set_commission` in the same block to raise their commission from 0% to 100%, with no enforced delay between the two operations. Delegators have no opportunity to exit before the next attestation distributes rewards at the new commission rate, resulting in theft of their unclaimed yield.

### Finding Description

The `set_commission_commitment` function in `src/staking/staking.cairo` creates a `CommissionCommitment { max_commission, expiration_epoch }` and writes it to storage immediately with no activation delay. [1](#0-0) 

The commitment is considered active as soon as `current_epoch < expiration_epoch`, meaning a commitment set with `expiration_epoch = current_epoch + 1` is active in the very same block it was created. [2](#0-1) 

Once an active commitment exists, `set_commission` → `update_commission` only enforces two checks: the new commission must be `<= max_commission` and must differ from the old commission. There is no lower bound preventing an increase. [3](#0-2) 

The codebase itself acknowledges this gap with a developer note directly above `set_commission_commitment`: [4](#0-3) 

Without a commitment, `set_commission` enforces `commission < old_commission` (decreases only). The commitment mechanism is the sole path to a commission increase, and it imposes no waiting period before the increase can be applied. [5](#0-4) 

### Impact Explanation

A staker who has attracted delegators at a low commission (e.g., 0%) can atomically:

1. Call `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)` — commitment is immediately active.
2. Call `set_commission(commission: 10000)` in the same block — commission jumps to 100%.

The next attestation call distributes epoch rewards using the new 100% commission rate, routing all delegator yield to the staker's reward address. Delegators cannot exit within the exit wait window (1 week) before the next attestation fires, so their accrued yield for that epoch is stolen.

This maps to **High: Theft of unclaimed yield**.

### Likelihood Explanation

- Any staker who has opened a delegation pool can execute this attack.
- No privileged role, leaked key, or external dependency is required.
- The attack is two sequential public transactions executable by the staker address alone.
- The code comment at line 745–746 confirms the developers are aware the safeguard is incomplete, making exploitation a known-possible path.

### Recommendation

Enforce a minimum delay between when a commission commitment is set and when it may be used to raise commission. For example, require that `expiration_epoch - current_epoch >= MIN_COMMITMENT_NOTICE_EPOCHS` where `MIN_COMMITMENT_NOTICE_EPOCHS` is large enough for delegators to observe the pending increase and submit an exit intent. Alternatively, make commission increases take effect only at the start of the next epoch after the commitment is set, giving delegators at least one full epoch of notice.

### Proof of Concept

```
// Staker has commission = 0, has a delegation pool with delegators.
// Block N, Epoch E:

// Step 1: Set commitment with max_commission = 10000, active immediately.
staking.set_commission_commitment(max_commission: 10000, expiration_epoch: E + 1);
// is_commission_commitment_active returns true: E < E+1

// Step 2: Raise commission to 100% in the same block.
staking.set_commission(commission: 10000);
// update_commission: 10000 <= 10000 ✓, 10000 != 0 ✓ → passes

// Step 3: Staker attests in the same epoch.
attestation.attest(block_hash);
// split_rewards_with_commission uses commission=10000 → 100% to staker, 0% to pool

// Delegators receive zero yield for this epoch.
// They cannot exit before the attestation because exit_wait_window = 1 week.
```

Relevant code paths: [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** src/staking/staking.cairo (L2178-2182)
```text
        fn is_commission_commitment_active(
            self: @ContractState, commission_commitment: CommissionCommitment,
        ) -> bool {
            self.get_current_epoch() < commission_commitment.expiration_epoch
        }
```
