### Title
Anyone Can Force a Delegator to Exit the Pool, Blocking Pool Switching - (`src/pool/pool.cairo`)

### Summary
`exit_delegation_pool_action` in `pool.cairo` has no caller restriction. After the exit window expires, any address can call it on behalf of a delegator, forcing them to receive their funds back and clearing their `unpool_time`. This prevents the delegator from calling `switch_delegation_pool` (which requires `unpool_time.is_some()`), forcing them to re-enter a new pool from scratch and lose yield during the re-delegation period.

### Finding Description
`exit_delegation_pool_action` (lines 295–333 of `src/pool/pool.cairo`) accepts a `pool_member` address as a parameter and performs **no caller validation**. The spec explicitly designates its access control as "Any address can execute." [1](#0-0) 

After the exit window expires, any address can call this function. The function:
1. Clears `pool_member_info.unpool_time` to `None`
2. Clears `pool_member_info.unpool_amount` to zero
3. Transfers funds to `pool_member` [2](#0-1) 

After this call, the delegator's `unpool_time` is `None`. The `switch_delegation_pool` function requires `pool_member_info.unpool_time.is_some()`: [3](#0-2) 

So the delegator can no longer switch pools atomically. Furthermore, when `exit_delegation_pool_intent(full_amount)` was originally called, `old_delegated_stake` was set to zero (the full amount moved to `unpool_amount`). After `exit_delegation_pool_action` clears `unpool_amount`, the delegator has `old_delegated_stake = 0` and `unpool_amount = 0`, so they cannot call `exit_delegation_pool_intent` again without first re-entering the pool. [4](#0-3) 

The spec confirms this is the intended design: [5](#0-4) 

However, the spec does not account for the griefing vector this creates against delegators who intend to switch pools.

### Impact Explanation
A malicious actor can grief a delegator by forcing them to exit the pool before they can switch to another pool. The delegator:
1. Receives their funds back (no direct fund loss)
2. Cannot call `switch_delegation_pool

### Citations

**File:** src/pool/pool.cairo (L256-278)
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
```

**File:** src/pool/pool.cairo (L295-303)
```text
        fn exit_delegation_pool_action(
            ref self: ContractState, pool_member: ContractAddress,
        ) -> Amount {
            // Asserts.
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let unpool_time = pool_member_info
                .unpool_time
                .expect_with_err(GenericError::MISSING_UNDELEGATE_INTENT);
            assert!(Time::now() >= unpool_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);
```

**File:** src/pool/pool.cairo (L321-330)
```text
            let unpool_amount = pool_member_info.unpool_amount;
            pool_member_info.unpool_amount = Zero::zero();
            pool_member_info.unpool_time = Option::None;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer delegated amount to the pool member.
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());
```

**File:** src/pool/pool.cairo (L386-393)
```text
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            assert!(
                pool_member_info.unpool_time.is_some(),
                "{}",
                GenericError::MISSING_UNDELEGATE_INTENT,
            );
```

**File:** docs/spec.md (L1999-2004)
```markdown
3. Staking contract is unpaused.
#### access control <!-- omit from toc -->
Any address can execute.
#### logic <!-- omit from toc -->
1. [Remove from delegation pool action](#remove_from_delegation_pool_action).
2. Transfer funds to pool member.
```
