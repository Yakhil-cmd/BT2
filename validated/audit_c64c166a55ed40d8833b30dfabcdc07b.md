### Title
Staker Can Raise Commission via Active Commitment to Steal Delegator Yield Without Slippage Protection — (File: `src/pool/pool.cairo`, `src/staking/staking.cairo`)

---

### Summary
`enter_delegation_pool` and `add_to_delegation_pool` accept no `max_commission` parameter. A staker can first set a `CommissionCommitment` with an arbitrarily high `max_commission`, then immediately raise commission to that ceiling after delegators have joined, redirecting nearly all pool rewards to themselves. Delegators have no on-chain protection against this sudden adverse rate change.

---

### Finding Description

`set_commission` normally only allows commission to be **decreased**: [1](#0-0) 

However, when a `CommissionCommitment` is active, the staker may set commission to **any value ≤ `max_commission`**, including values **higher** than the current commission: [2](#0-1) 

`set_commission_commitment` only requires `max_commission >= current_commission`, so a staker with 1% commission can set `max_commission = 9999` (99.99%) immediately: [3](#0-2) 

The code itself acknowledges this gap: [4](#0-3) 

Commission is read at reward-calculation time with no snapshot or delay: [5](#0-4) 

Meanwhile, `enter_delegation_pool` and `add_to_delegation_pool` accept no `max_commission` guard: [6](#0-5) [7](#0-6) 

---

### Impact Explanation

After the staker raises commission to 9999 (99.99%), `split_rewards_with_commission` routes almost the entire pool reward to the staker as commission, leaving delegators with ~0.01% of what they were entitled to. This constitutes **theft of unclaimed yield** (rewards not yet distributed to delegators).

Impact: **High — Theft of unclaimed yield.**

---

### Likelihood Explanation

The attack is two steps (`set_commission_commitment` then `set_commission`), both permissionless for any registered staker. No privileged role, leaked key, or external dependency is required. A rational staker can execute this atomically or within the same epoch. Delegators monitoring only the current commission (not pending commitments) are fully exposed.

Likelihood: **Medium** — requires deliberate setup but is straightforward to execute.

---

### Recommendation

Add a `max_commission` parameter to `enter_delegation_pool` and `add_to_delegation_pool`, validated against the pool's current commission at call time:

```rust
fn enter_delegation_pool(
    ref self: ContractState,
    reward_address: ContractAddress,
    amount: Amount,
    max_commission: Commission,   // <-- slippage guard
) {
    let current_commission = self.get_commission_from_staking_contract();
    assert!(current_commission <= max_commission, "Commission exceeds max_commission");
    // ... rest of logic
}
```

This mirrors the recommendation in the external report (`buydPNM(uint BUSDamount, uint minAmountdPNMReceived)`): an undesirable rate change causes the transaction to revert rather than silently harming the user.

---

### Proof of Concept

```
1. Staker calls stake() and set_commission(commission: 100)   // 1%
2. Staker calls set_commission_commitment(
       max_commission: 9999,          // 99.99%
       expiration_epoch: current + 1  // valid: > current, ≤ current + epochs_in_year
   )
   → Passes: current_commission (100) <= max_commission (9999)  [line 770]

3. Delegator calls enter_delegation_pool(reward_address, amount)
   → Sees 1% commission; no max_commission check exists  [line 182-219]

4. Staker calls set_commission(commission: 9999)
   → Passes: commitment is active, 9999 <= max_commission (9999), 9999 != 100  [lines 1583-1589]
   → Commission is written to storage immediately  [line 1600]

5. update_rewards / attest is called
   → commission = staker_pool_info.commission() = 9999  [line 1964]
   → split_rewards_with_commission routes 99.99% to staker  [line 1989-1991]
   → Delegator receives ~0.01% of entitled rewards
```

### Citations

**File:** src/staking/staking.cairo (L745-747)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
        /// **Note**: Updating epoch info can impact the commission commitment expiration date.
```

**File:** src/staking/staking.cairo (L769-778)
```text
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

**File:** src/pool/pool.cairo (L182-184)
```text
        fn enter_delegation_pool(
            ref self: ContractState, reward_address: ContractAddress, amount: Amount,
        ) {
```

**File:** src/pool/pool.cairo (L221-223)
```text
        fn add_to_delegation_pool(
            ref self: ContractState, pool_member: ContractAddress, amount: Amount,
        ) -> Amount {
```
