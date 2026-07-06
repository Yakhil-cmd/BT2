### Title
Staker Can Retroactively Increase Commission Mid-Epoch to Steal Delegator Yield - (`src/staking/staking.cairo`)

### Summary

A staker can use `set_commission_commitment` followed by `set_commission` to increase their commission rate within an active epoch, immediately before calling `attest` (which triggers reward settlement). Because `calculate_staker_pools_rewards` reads commission from live storage at settlement time rather than from an epoch-snapshotted value, the increased commission is applied retroactively to the entire epoch's rewards, stealing yield from delegators.

### Finding Description

The reward settlement path reads the staker's commission directly from current storage at the moment `update_rewards` / `attest` is called: [1](#0-0) 

This is inside `calculate_staker_pools_rewards`, which is called by `_update_rewards`: [2](#0-1) 

The commission is not epoch-snapshotted. It is a single mutable storage value that can be changed at any time by the staker.

The `set_commission_commitment` function allows a staker to set a commitment with a `max_commission` ceiling that is **higher** than the current commission: [3](#0-2) 

Once a commitment is active, `set_commission` permits raising commission up to `max_commission`: [4](#0-3) 

The attack sequence:
1. Staker has commission = 5% (500 bps).
2. Staker calls `set_commission_commitment(max_commission: 5000, expiration_epoch: current_epoch + 1)`.
3. Delegators join the pool, expecting 5% commission.
4. Epoch progresses; delegators earn rewards.
5. Just before attestation, staker calls `set_commission(5000)` — raises commission to 50%.
6. Staker calls `attest`, triggering `update_rewards_from_attestation_contract` → `_update_rewards`.
7. The 50% commission is applied to the **entire epoch's** pool rewards.
8. Delegators receive 50% less than they were entitled to.

The commission split is computed and applied at settlement: [5](#0-4) 

### Impact Explanation

Delegators lose a portion of their earned-but-unclaimed yield for the epoch in which the commission was raised. The staker captures the difference as commission rewards. This is a direct theft of unclaimed yield from delegators.

**Impact: High** — matches "Theft of unclaimed yield."

### Likelihood Explanation

Any staker with a delegation pool can execute this attack. The only prerequisite is calling `set_commission_commitment` once (which is permissionless for any staker). The staker can then time the commission increase to just before attestation in any epoch. The attack is repeatable every commitment period (up to 1 year per commitment).

**Likelihood: Medium** — requires a malicious staker, but no privileged access or external dependencies.

### Recommendation

Snapshot the commission value at the start of each epoch (analogous to how staker and delegator balances are snapshotted via the balance trace). When computing pool rewards for epoch `N`, use the commission value that was in effect at the beginning of epoch `N`, not the value at settlement time. Alternatively, enforce that commission changes only take effect starting from `current_epoch + K + 1`, consistent with the balance trace delay already used for stake amounts.

### Proof of Concept

```
1. Deploy staking system with staker S and delegator D.
2. S stakes with commission = 500 (5%).
3. S calls set_commission_commitment(max_commission: 5000, expiration_epoch: current_epoch + 1).
4. D enters delegation pool.
5. Advance K epochs (rewards accrue).
6. S calls set_commission(5000) — commission is now 50%, effective immediately in storage.
7. S calls attest() — triggers _update_rewards.
8. calculate_staker_pools_rewards reads commission = 5000 from storage.
9. split_rewards_with_commission applies 50% commission to pool rewards.
10. D receives 50% less STRK than expected.
11. Assert: actual_pool_rewards < expected_pool_rewards_at_5pct_commission.
```

The root cause is at: [6](#0-5) 

compared to the balance trace which correctly snapshots values at `epoch + K`: [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L769-771)
```text
            let current_commission = staker_pool_info.commission();
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

**File:** src/staking/staking.cairo (L1964-1993)
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
                total_commission_rewards += commission_rewards;
                total_pools_rewards += pool_rewards;
```

**File:** src/staking/staking.cairo (L2008-2014)
```text
        fn insert_staker_own_balance(
            ref self: ContractState, staker_address: ContractAddress, own_balance: NormalizedAmount,
        ) {
            self
                .staker_own_balance_trace
                .entry(staker_address)
                .insert(key: self.get_epoch_plus_k(), value: own_balance.to_strk_native_amount());
```

**File:** src/staking/staking.cairo (L2332-2346)
```text
            let (commission_rewards, total_pools_rewards, pools_rewards_data) = if staker_pool_info
                .has_pool() {
                self
                    .calculate_staker_pools_rewards(
                        :staker_address,
                        :staker_pool_info,
                        :strk_total_rewards,
                        :strk_total_stake,
                        :btc_total_rewards,
                        :btc_total_stake,
                        :curr_epoch,
                    )
            } else {
                (Zero::zero(), Zero::zero(), array![])
            };
```
