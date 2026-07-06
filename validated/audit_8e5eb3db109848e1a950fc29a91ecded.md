### Title
Staker Can Exploit `set_commission_commitment` to Instantly Raise Commission to 100%, Stealing Delegators' Yield - (File: src/staking/staking.cairo)

### Summary
The `set_commission_commitment` + `set_commission` two-step mechanism allows a staker to bypass the normal "commission can only decrease" invariant and instantly raise their commission to any value up to `COMMISSION_DENOMINATOR` (10000 = 100%). A malicious staker can exploit this to steal all pool rewards from delegators for any epoch where rewards have not yet been calculated.

### Finding Description
Under normal operation, `set_commission` enforces a strict decrease-only rule:

```cairo
} else {
    assert!(commission < old_commission, "{}", Error::INVALID_COMMISSION);
}
``` [1](#0-0) 

However, when an active commission commitment exists, this check is replaced with a weaker one that only requires `commission ≤ max_commission`:

```cairo
if self.is_commission_commitment_active(:commission_commitment) {
    assert!(
        commission <= commission_commitment.max_commission, ...
    );
    assert!(commission != old_commission, ...);
}
``` [2](#0-1) 

Since `max_commission` can be set to `COMMISSION_DENOMINATOR` (10000 = 100%) — the only constraint being `max_commission >= current_commission` — a staker can:

1. Set a low commission (e.g., 500 = 5%) to attract delegators.
2. Call `set_commission_commitment(max_commission=10000, expiration_epoch=current_epoch+1)`.
3. Immediately call `set_commission(commission=10000)` in the same block.
4. When rewards are calculated, the commission read from storage is 100%. [3](#0-2) 

The commission is applied at reward-calculation time inside `calculate_staker_pools_rewards`:

```cairo
let commission = staker_pool_info.commission();
``` [4](#0-3) 

The reward split then routes 100% of pool rewards to the staker as commission, leaving delegators with zero:

```cairo
let (commission_rewards, pool_rewards) = split_rewards_with_commission(
    rewards_including_commission: pool_rewards_including_commission, :commission,
);
``` [5](#0-4) 

The codebase itself acknowledges this gap with an explicit warning comment directly above `set_commission_commitment`:

> **Note**: Current commission increase safeguards still allow for sudden commission changes. [6](#0-5) 

### Impact Explanation
All pool rewards for the epoch in which the commission is raised to 100% are redirected to the staker as commission. Delegators who have been providing stake for that epoch receive zero yield. This constitutes **theft of unclaimed yield** (High severity): delegators have earned rewards by locking stake, but those rewards are diverted before they can be calculated and distributed.

### Likelihood Explanation
The attack requires only two sequential transactions (`set_commission_commitment` then `set_commission`) that can be submitted in the same block. There is no time-lock, no delay, and no minimum notice period before the new commission takes effect. Delegators have no on-chain mechanism to react before the next reward calculation. Any staker with an active pool and delegators can execute this at will.

### Recommendation
Introduce a mandatory delay (e.g., at least one full epoch) between the moment a commission commitment is set and the moment a commission *increase* can take effect. This gives delegators time to observe the commitment event and exit the pool via `exit_delegation_pool_intent` before the higher commission is applied. Alternatively, cap `max_commission` at the current commission plus a small increment per epoch to prevent sudden jumps to 100%.

### Proof of Concept
1. Staker stakes and calls `set_commission(commission=500)` (5%).
2. Delegators call `add_to_delegation_pool` and begin earning rewards.
3. Staker calls `set_commission_commitment(max_commission=10000, expiration_epoch=current_epoch+1)`.
4. Staker immediately calls `set_commission(commission=10000)` (100%) — succeeds because `10000 ≤ max_commission` and `10000 ≠ 500`.
5. `update_rewards_from_attestation_contract` (or `update_rewards`) is called: `commission = staker_pool_info.commission()` returns 10000; `split_rewards_with_commission` routes 100% of pool rewards to the staker.
6. Pool contract receives zero rewards; delegators' `unclaimed_rewards` remain zero for that epoch. [7](#0-6) [8](#0-7)

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

**File:** src/staking/staking.cairo (L1573-1608)
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
