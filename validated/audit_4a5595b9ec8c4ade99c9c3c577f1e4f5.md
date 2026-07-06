### Title
Commission Updated Without Prior Reward Checkpoint Allows Staker to Steal Delegator Yield - (File: src/staking/staking.cairo)

---

### Summary

`set_commission` in `staking.cairo` writes a new commission rate to storage immediately, without first distributing accumulated rewards to delegators. When a staker holds an active `CommissionCommitment`, they can increase commission to any value up to `max_commission` (including 100%) mid-epoch. The next reward distribution event then applies the new, higher commission to the **entire epoch's** pool rewards, retroactively zeroing out delegators' yield for that epoch.

---

### Finding Description

The internal `update_commission` function writes the new commission directly to storage with no prior reward checkpoint:

```cairo
// Update commission in storage.
staker_pool_info.commission.write(Option::Some(commission));
```

At reward distribution time (`update_rewards_from_attestation_contract` in V2, `update_rewards` in V3), `calculate_staker_pools_rewards` reads the **current** commission from storage and applies it to the full epoch/block reward:

```cairo
let commission = staker_pool_info.commission();   // reads live storage
...
let (commission_rewards, pool_rewards) = split_rewards_with_commission(
    rewards_including_commission: pool_rewards_including_commission, :commission,
);
```

There is no per-epoch or per-block commission snapshot. Whatever commission is stored at the moment of reward calculation is applied to the entire period's rewards.

The `CommissionCommitment` mechanism explicitly allows commission **increases**: while a commitment is active (`current_epoch < expiration_epoch`), the only constraint is `commission <= max_commission` and `commission != old_commission`. A commitment set in epoch N with `expiration_epoch = N+1` is immediately active, so the staker can set the commitment and raise commission to `max_commission` in the same epoch, before the attestation window.

The code itself acknowledges this gap:

```cairo
/// **Note**: Current commission increase safeguards still allow for sudden commission
/// changes.
fn set_commission_commitment(...)
```

---

### Impact Explanation

A staker with delegators can steal the delegators' entire epoch reward in V2 (pre-consensus) or entire block reward in V3 (consensus). In V2 the impact is larger: one epoch's worth of pool rewards can be fully redirected to the staker as commission. Delegators cannot exit in time because the exit process requires `exit_delegation_pool_intent` followed by a mandatory `exit_wait_window` delay. This matches **High: Theft of unclaimed yield**.

---

### Likelihood Explanation

Medium. The staker must first call `set_commission_commitment` with a high `max_commission`, then call `set_commission` before the attestation window. Both steps are public on-chain, but the window between commitment and attestation can be very short (same epoch). The staker has a direct financial incentive (capturing 100% of pool rewards as commission). After the attack the staker can lower commission again to attract new delegators, making the attack repeatable.

---

### Recommendation

Apply commission changes only at epoch boundaries (i.e., store a `(pending_commission, effective_epoch)` pair and activate it at the start of the next epoch), mirroring the K-epoch delay already used for stake balance changes. This ensures that any reward distribution within the current epoch always uses the commission that was in effect at the start of that epoch.

---

### Proof of Concept

**Setup**: Staker S has commission = 200 (2%), a STRK pool, and delegator D with a large delegated balance. Epoch N is in progress; attestation has not yet occurred.

**Attack steps (all in epoch N, before attestation)**:

1. S calls `set_commission_commitment(max_commission: 10000, expiration_epoch: N+1)`.
   - Commitment is immediately active because `is_commission_commitment_active` checks `current_epoch < expiration_epoch` → `N < N+1` ✓
2. S calls `set_commission(commission: 10000)`.
   - `update_commission` validates `commission (10000) <= max_commission (10000)` ✓ and `commission != old_commission` ✓.
   - Writes `commission = 10000` to storage. **No reward update is triggered.**
3. S (or anyone) calls `attest` for S's operational address.
   - `update_rewards_from_attestation_contract` → `_update_rewards` → `calculate_staker_pools_rewards`.
   - Line 1964: `let commission = staker_pool_info.commission();` → reads **10000**.
   - `split_rewards_with_commission` with commission = 10000 → `pool_rewards = 0`, `commission_rewards = full pool share`.
   - D receives **0 rewards** for epoch N; S receives 100% of the pool's epoch rewards as commission.

**Result**: D's entire epoch yield is stolen by S. D had no opportunity to exit before the commission change took effect. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** src/staking/staking.cairo (L1963-1991)
```text
            let mut total_pools_rewards: Amount = Zero::zero();
            let commission = staker_pool_info.commission();
            for (pool_contract, token_address) in staker_pool_info.pools {
                if !self.is_active_token(:token_address, epoch_id: curr_epoch) {
                    continue;
                }
                let pool_balance_curr_epoch = self
                    .get_staker_delegated_balance_at_epoch(
                        :staker_address, :pool_contract, epoch_id: curr_epoch,
                    );
                let (total_rewards, total_stake) = if token_address == STRK_TOKEN_ADDRESS {
                    (strk_total_rewards, strk_total_stake)
                } else {
                    (btc_total_rewards, btc_total_stake)
                };
                // Calculate rewards for this pool.
                let pool_rewards_including_commission = if total_stake.is_non_zero() {
                    mul_wide_and_div(
                        lhs: total_rewards,
                        rhs: pool_balance_curr_epoch.to_amount_18_decimals(),
                        div: total_stake.to_amount_18_decimals(),
                    )
                        .expect_with_err(err: InternalError::REWARDS_COMPUTATION_OVERFLOW)
                } else {
                    Zero::zero()
                };
                let (commission_rewards, pool_rewards) = split_rewards_with_commission(
                    rewards_including_commission: pool_rewards_including_commission, :commission,
                );
```

**File:** src/staking/staking.cairo (L2178-2182)
```text
        fn is_commission_commitment_active(
            self: @ContractState, commission_commitment: CommissionCommitment,
        ) -> bool {
            self.get_current_epoch() < commission_commitment.expiration_epoch
        }
```
