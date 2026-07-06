### Title
Staker Can Instantly Raise Commission to 100% via Commitment Mechanism, Stealing All Delegator Yield - (File: src/staking/staking.cairo)

---

### Summary

A staker can atomically set a commission commitment with `max_commission = 10000` (100%) and immediately call `set_commission(10000)` in the same transaction sequence, jumping from any low commission to 100% with no delay. All delegator rewards calculated after that point are entirely captured by the staker, leaving delegators with zero yield.

---

### Finding Description

The `set_commission_commitment` function in `src/staking/staking.cairo` accepts any `max_commission` up to `COMMISSION_DENOMINATOR` (10000 = 100%) and requires only that `expiration_epoch > current_epoch`, meaning the minimum valid commitment is `expiration_epoch = current_epoch + 1`. [1](#0-0) 

Once a commitment is active (`current_epoch < expiration_epoch`), the `update_commission` internal function enforces only two constraints:

1. `commission <= commitment.max_commission`
2. `commission != old_commission` [2](#0-1) 

There is no constraint preventing an upward jump. A staker starting at 0% commission can therefore:

1. Call `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)` — commitment is immediately active.
2. Call `set_commission(commission: 10000)` in the same block — commission jumps to 100%.

The developers themselves acknowledge this gap in a code comment directly above `set_commission_commitment`: [3](#0-2) 

> **Note**: Current commission increase safeguards still allow for sudden commission changes.

When rewards are subsequently calculated (in `calculate_staker_pools_rewards`), the commission is read live from storage: [4](#0-3) 

`split_rewards_with_commission` with `commission = 10000` yields `commission_rewards = pool_rewards_including_commission` and `pool_rewards = 0`, so the delegation pool receives nothing. [5](#0-4) 

---

### Impact Explanation

**High — Theft of unclaimed yield.**

Delegators who have staked tokens in the pool earn zero rewards for every epoch in which the staker holds 100% commission. The staker captures the entire delegated-stake reward share. Because `calculate_staker_pools_rewards` reads the live commission value at reward-calculation time, any rewards not yet distributed when the commission is raised to 100% are fully redirected to the staker. Delegators receive `pool_rewards = 0`.

---

### Likelihood Explanation

**Medium.** Any staker who has opened a delegation pool can execute this two-step sequence permissionlessly at any time. No privileged role, leaked key, or external dependency is required. The only prerequisite is that the staker has a pool (`has_pool()` must be true). The attack is cheap (two transactions) and can be timed to coincide with a large accumulated reward balance in the pool, maximising the stolen amount. The code comment at line 745–746 confirms the developers are aware the safeguard is incomplete.

---

### Recommendation

1. **Cap `max_commission` in `set_commission_commitment`** to a protocol-defined maximum (e.g., 30%), mirroring the external report's recommendation to limit the fee rate.
2. **Enforce a minimum delay** between setting a commitment and being allowed to increase commission — for example, require that the commitment was set at least one full epoch before it can be used to raise the rate.
3. **Apply commission changes prospectively**: record the epoch in which the commission was changed and use the old commission for any epoch that started before the change.

---

### Proof of Concept

```
// Epoch N, staker has commission = 0, pool has delegators.

// Step 1: set commitment with max = 100%, active immediately.
staking.set_commission_commitment(
    max_commission: 10000,          // COMMISSION_DENOMINATOR
    expiration_epoch: current_epoch + 1,  // active for epoch N
);

// Step 2: jump to 100% commission in the same epoch.
staking.set_commission(commission: 10000);

// Now: calculate_staker_pools_rewards reads commission = 10000.
// split_rewards_with_commission(rewards, 10000)
//   => commission_rewards = rewards * 10000 / 10000 = rewards
//   => pool_rewards = rewards - rewards = 0
// Delegators receive 0 yield; staker captures 100% of delegated rewards.
```

The two calls satisfy all on-chain checks:
- `set_commission_commitment`: `max_commission (10000) <= COMMISSION_DENOMINATOR (10000)` ✓, `expiration_epoch (N+1) > current_epoch (N)` ✓, no existing active commitment ✓.
- `set_commission`: `commission (10000) <= COMMISSION_DENOMINATOR` ✓, commitment is active (`N < N+1`) ✓, `commission (10000) != old_commission (0)` ✓.

### Citations

**File:** src/staking/staking.cairo (L745-746)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
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

**File:** src/staking/staking.cairo (L1583-1597)
```text
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
