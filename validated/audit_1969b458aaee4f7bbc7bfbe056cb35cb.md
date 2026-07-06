### Title
Commission Increase Applied Retroactively to Current Reward Period — (`src/staking/staking.cairo`)

---

### Summary

`set_commission()` immediately overwrites the stored commission without first settling rewards for the elapsed period. When the next reward distribution call (`update_rewards_from_attestation_contract` in V2 / `update_rewards` in V3) executes, it reads the **new** commission from storage and applies it to the **entire elapsed period**, retroactively extracting more commission from delegators' already-accrued yield.

---

### Finding Description

**Root cause — `set_commission` writes immediately, no prior accrual:**

`set_commission` (and its internal helper `update_commission`) writes the new commission value directly to storage with no prior reward settlement: [1](#0-0) [2](#0-1) 

**Root cause — reward calculation reads the current (already-updated) commission:**

`calculate_staker_pools_rewards`, called from every reward distribution path, reads commission from storage at distribution time: [3](#0-2) [4](#0-3) 

**Commission increase is possible via `set_commission_commitment`:**

Without a commitment, commission can only decrease. With an active commitment, `update_commission` allows setting commission to any value `<= max_commission` (which can be higher than the current commission): [5](#0-4) 

The spec confirms `max_commission >= current_commission` is the only constraint on the commitment value. [6](#0-5) 

**V2 attestation path — staker controls timing:**

In pre-consensus (V2) mode, `update_rewards_from_attestation_contract` is triggered by the staker's own `attest()` call. The staker controls exactly when within the epoch they attest: [7](#0-6) 

The entire epoch's rewards are then split using whatever commission is in storage at that moment: [8](#0-7) 

---

### Impact Explanation

A staker who has set a commission commitment with `max_commission` higher than their current commission can:

1. Let an entire epoch accumulate delegator rewards at the old (low) commission.
2. Call `set_commission(commission: max_commission)` immediately before attesting.
3. The single `update_rewards_from_attestation_contract` call distributes the **full epoch's** pool rewards using the **new higher** commission.

Delegators receive `(1 − new_commission)` of pool rewards instead of `(1 − old_commission)` for the entire epoch. The difference — `(new_commission − old_commission) × pool_rewards` — is silently redirected to the staker. This is **theft of unclaimed yield** from delegators.

For a pool with large delegated stake and a commitment that allows e.g. a 45-percentage-point commission jump (5% → 50%), delegators lose nearly half their epoch's yield in a single transaction.

---

### Likelihood Explanation

- Any staker can call `set_commission_commitment` to establish a higher `max_commission` at any time (no privileged role required).
- The staker fully controls the timing of their `attest()` call within the attestation window.
- The attack requires no external dependencies, no leaked keys, and no third-party compromise.
- The staker has a direct financial incentive to execute this.
- The developer comment at line 745–747 acknowledges "current commission increase safeguards still allow for sudden commission changes," suggesting awareness of the gap but no fix. [9](#0-8) 

---

### Recommendation

Before writing the new commission to storage in `set_commission` / `update_commission`, the contract should first settle (accrue) all pending rewards for the current period using the old commission. This mirrors the correct pattern: settle first, then update the rate parameter. Concretely, `set_commission` should internally trigger the equivalent of `update_rewards_from_attestation_contract` (V2) or record a checkpoint so that the next `update_rewards` call only applies the new commission to blocks/epochs that begin **after** the change.

---

### Proof of Concept

**Setup (V2 attestation mode):**

1. Staker stakes with commission = 500 (5%).
2. Staker calls `set_commission_commitment(max_commission: 5000, expiration_epoch: current_epoch + 1)`.
3. Delegator delegates a large amount to the staker's pool.
4. Epoch N begins; delegators accumulate rewards at 5% commission throughout the epoch.

**Attack (end of epoch N, before attesting):**

5. Staker calls `set_commission(commission: 5000)` — commission jumps to 50%.
   - `update_commission` at line 1573 passes the commitment check (`5000 <= 5000`, `5000 != 500`).
   - Line 1600 writes `commission = 5000` to storage immediately.

6. Staker's operational address calls `attest()` → attestation contract calls `update_rewards_from_attestation_contract(staker_address)`.

7. Inside `_update_rewards` → `calculate_staker_pools_rewards`:
   - Line 1964: `let commission = staker_pool_info.commission();` → reads **5000** (50%).
   - Line 1989–1991: `split_rewards_with_commission` splits the **entire epoch's** pool rewards at 50%.

8. Delegators receive 50% of pool rewards instead of 95% — losing 45% of their epoch N yield to the staker. [10](#0-9) [11](#0-10)

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

**File:** src/staking/staking.cairo (L1394-1423)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);

            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
            // Get current epoch data.
            let (strk_epoch_rewards, btc_epoch_rewards) = reward_supplier_dispatcher
                .calculate_current_epoch_rewards();
            let (strk_total_stake, btc_total_stake) = self.get_current_total_staking_power();
            let staker_pool_info = self.staker_pool_info.entry(staker_address).as_non_mut();
            let curr_epoch = self.get_current_epoch();
            self
                ._update_rewards(
                    :staker_address,
                    strk_total_rewards: strk_epoch_rewards,
                    btc_total_rewards: btc_epoch_rewards,
                    :strk_total_stake,
                    :btc_total_stake,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
        }
```

**File:** src/staking/staking.cairo (L1580-1601)
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

**File:** src/staking/staking.cairo (L1964-1991)
```text
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

**File:** docs/spec.md (L983-984)
```markdown
6. `max_commission` should be greater than or equal to the current commission.
7. `expiration_epoch` should be greater than the current epoch.
```
