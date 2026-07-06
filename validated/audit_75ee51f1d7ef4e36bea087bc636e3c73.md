### Title
Staker Can Suddenly Increase Commission via Commitment Mechanism, Stealing Delegator Yield With No Slippage Protection - (File: src/staking/staking.cairo)

---

### Summary
`enter_delegation_pool` and `add_to_delegation_pool` accept no `max_commission` parameter. A staker can atomically set a commission commitment with `max_commission` above the current rate and then immediately raise the commission to that ceiling, reducing delegator yield to zero with no recourse. The protocol's own code acknowledges this gap.

---

### Finding Description

**Root cause — two-step commission increase:**

`set_commission_commitment` (staking.cairo:748–785) enforces only that `max_commission >= current_commission`: [1](#0-0) 

There is no upper bound below `COMMISSION_DENOMINATOR` (10 000 = 100 %), and no time-lock between setting the commitment and using it.

`update_commission` (staking.cairo:1573–1609) then permits the commission to be set to **any** value ≤ `max_commission` — including values **higher** than the current commission — as long as an active commitment exists: [2](#0-1) 

Without a commitment the only allowed direction is downward: [3](#0-2) 

The protocol's own NatSpec acknowledges the gap: [4](#0-3) 

**Missing protection on the delegator side:**

`enter_delegation_pool` accepts only `reward_address` and `amount`; there is no `max_commission` guard: [5](#0-4) 

`add_to_delegation_pool` is identical in this regard: [6](#0-5) 

A delegator who approves tokens and calls either function has no way to bound the commission rate that will apply to their yield.

---

### Impact Explanation

A malicious staker executes two transactions in the same block (or back-to-back):

1. `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)` — sets a commitment allowing 100 % commission.
2. `set_commission(commission: 10000)` — raises commission to 100 %.

At the next attestation the staking contract reads the commission from storage: [7](#0-6) 

All pool rewards are routed to the staker as commission; delegators receive zero. This is **theft of unclaimed yield** (High severity). Delegators can exit, but the mandatory `DEFAULT_EXIT_WAIT_WINDOW` means they are subject to the inflated commission for at least one full exit period.

---

### Likelihood Explanation

Any staker who has opened a delegation pool can execute this in two permissionless transactions. No privileged role, leaked key, or external dependency is required. The staker has a direct financial incentive (capturing 100 % of pool rewards). Likelihood is **High**.

---

### Recommendation

Add a `max_commission: Commission` parameter to both `enter_delegation_pool` and `add_to_delegation_pool` in `src/pool/pool.cairo`. After reading the current commission from the staking contract, assert:

```cairo
assert!(current_commission <= max_commission, Error::COMMISSION_EXCEEDS_MAX);
```

This gives delegators the same slippage protection that the vault-purchase report recommended via `maxAmount`: if the commission has been raised above the delegator's tolerance before their transaction executes, the call reverts rather than silently reducing their yield.

---

### Proof of Concept

```
// Setup
staker.stake(amount, pool_enabled: true, commission: 500);   // 5 %
delegator.enter_delegation_pool(reward_addr, amount);        // no max_commission guard

// Attack (two txs, same block)
staker.set_commission_commitment(max_commission: 10000, expiration_epoch: epoch + 1);
staker.set_commission(commission: 10000);                    // now 100 %

// Next attestation
staker.attest(block_hash);
// → split_rewards_with_commission applied with commission = 10000
// → pool_rewards = 0, commission_rewards = total pool share
// → delegator.claim_rewards() returns 0
``` [8](#0-7) [9](#0-8)

### Citations

**File:** src/staking/staking.cairo (L745-746)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
```

**File:** src/staking/staking.cairo (L769-770)
```text
            let current_commission = staker_pool_info.commission();
            assert!(current_commission <= max_commission, "{}", Error::MAX_COMMISSION_TOO_LOW);
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

**File:** src/pool/pool.cairo (L182-199)
```text
        fn enter_delegation_pool(
            ref self: ContractState, reward_address: ContractAddress, amount: Amount,
        ) {
            // Asserts.
            self.assert_staker_is_active();
            let pool_member = get_caller_address();
            assert!(
                self.pool_member_info.read(pool_member).is_none(), "{}", Error::POOL_MEMBER_EXISTS,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let token_dispatcher = self.token_dispatcher.read();
            let token_address = token_dispatcher.contract_address;
            assert!(token_address != pool_member, "{}", Error::POOL_MEMBER_IS_TOKEN);
            assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
            // Transfer funds from the delegator to the staking contract.
            let staker_address = self.staker_address.read();
            transfer_from_delegator(:pool_member, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);
```

**File:** src/pool/pool.cairo (L221-223)
```text
        fn add_to_delegation_pool(
            ref self: ContractState, pool_member: ContractAddress, amount: Amount,
        ) -> Amount {
```
