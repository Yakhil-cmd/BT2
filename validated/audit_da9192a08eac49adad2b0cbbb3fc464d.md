### Title
Delegator Can Indefinitely Reset Exit Window Timer via `exit_delegation_pool_intent` - (File: src/pool/pool.cairo)

### Summary
A delegator can repeatedly call `exit_delegation_pool_intent` with the same amount to reset the `unpool_time` timer, keeping the staker's delegated balance artificially reduced indefinitely and maintaining a perpetual free-look exit option.

### Finding Description
The `exit_delegation_pool_intent` function in `src/pool/pool.cairo` calls `undelegate_from_staking_contract_intent`, which calls `remove_from_delegation_pool_intent` in the staking contract, which calls `update_undelegate_intent_value`.

`update_undelegate_intent_value` **always** recalculates `unpool_time` as `Time::now() + exit_wait_window`, unconditionally overwriting any existing timer: [1](#0-0) 

The interface documentation explicitly confirms this behavior: [2](#0-1) 

Because `exit_delegation_pool_intent` computes `total_amount = old_delegated_stake + pool_member_info.unpool_amount`, calling it again with the same `unpool_amount` is always valid (the amount check passes), and the only effect is resetting `unpool_time` to `Time::now() + exit_wait_window` with no balance change: [3](#0-2) 

The staking contract's `remove_from_delegation_pool_intent` reads the old intent amount and computes `new_delegated_stake` via `compute_new_delegated_stake`. When `old_intent_amount == new_intent_amount`, the staker's delegated balance is unchanged — only `unpool_time` is refreshed: [4](#0-3) 

### Impact Explanation
When a delegator first calls `exit_delegation_pool_intent(amount)`, the staker's delegated balance is reduced by `amount`, removing it from the staker's staking power and reward calculation. By resetting the timer just before it expires (every ~1 week), the delegator keeps the staker's balance permanently reduced without ever actually exiting. The staker loses unclaimed yield proportional to `unpool_amount` for the entire duration of the attack. For a large delegator, the cost (lost rewards on the exiting amount) can be outweighed by the benefit of maintaining a perpetual exit option — for example, to exit immediately before a staker is penalized or slashed. This constitutes griefing with measurable financial damage to the staker.

### Likelihood Explanation
Any delegator can execute this. The only cost is gas (low on Starknet L2) and foregone rewards on the `unpool_amount`. For large positions, the attack is economically rational. No special access or privilege is required — `exit_delegation_pool_intent` is callable by any pool member.

### Recommendation
Do not reset `unpool_time` when the new intent amount equals the existing intent amount. Alternatively, require a minimum elapsed time between intent updates (analogous to `REQUEST_EXPIRATION_BLOCK_AGE` in the GMX fix), so that the timer can only be reset after a meaningful delay has passed since the last update.

### Proof of Concept
1. Delegator calls `exit_delegation_pool_intent(X)` at time T. Staker's delegated balance is reduced by X. `unpool_time = T + exit_wait_window`.
2. At time T + exit_wait_window − ε, delegator calls `exit_delegation_pool_intent(X)` again. Since `total_amount = 0 + X = X` and `amount = X ≤ total_amount`, the call succeeds. `unpool_time` is reset to `(T + exit_wait_window − ε) + exit_wait_window`.
3. Staker's delegated balance remains reduced. No funds move. Repeat indefinitely.
4. The staker loses staking power and rewards on X for the entire duration. The delegator retains the ability to execute the exit at any moment within the current window.

### Citations

**File:** src/staking/staking.cairo (L1066-1083)
```text
            // Update the delegated stake according to the new intent.
            let undelegate_intent_key = UndelegateIntentKey { pool_contract, identifier };
            let old_intent_amount = self.get_pool_exit_intent(:undelegate_intent_key).amount;
            let new_intent_amount = normalized_amount;
            // After this call, the staker balance will be updated.
            let (old_delegated_stake, new_delegated_stake) = self
                .update_delegated_stake(
                    :staker_address,
                    :token_address,
                    :pool_contract,
                    :staker_info,
                    :old_intent_amount,
                    :new_intent_amount,
                );
            self
                .update_undelegate_intent_value(
                    :token_address, :staker_info, :undelegate_intent_key, :new_intent_amount,
                );
```

**File:** src/staking/staking.cairo (L1833-1849)
```text
        fn update_undelegate_intent_value(
            ref self: ContractState,
            token_address: ContractAddress,
            staker_info: InternalStakerInfoLatest,
            undelegate_intent_key: UndelegateIntentKey,
            new_intent_amount: NormalizedAmount,
        ) {
            let undelegate_intent_value = if new_intent_amount.is_zero() {
                Zero::zero()
            } else {
                let unpool_time = staker_info
                    .compute_unpool_time(exit_wait_window: self.exit_wait_window.read());
                assert!(token_address.is_non_zero(), "{}", InternalError::TOKEN_IS_ZERO_ADDRESS);
                UndelegateIntentValue { amount: new_intent_amount, unpool_time, token_address }
            };
            self.pool_exit_intents.write(undelegate_intent_key, undelegate_intent_value);
        }
```

**File:** src/staking/interface.cairo (L179-186)
```text
    /// The function supports overriding intentions, upwards and downwards, *which recalculates the
    /// unpool_time and restarts the timer*. This slightly changes the flow, meaning that if the
    /// pool already has an intent for this `identifier`, the flow remains the same except for
    /// points 2 and 3:
    /// * If the amount to be removed is greater in the previous intent, the staker's pooled amount
    ///   and total_stake will be *decreased* by the difference between the new and the old amount.
    /// * If the amount to be removed is smaller in the previous intent, the staker's pooled amount
    ///   and total_stake will be *increased* by the difference between the old and the new amount.
```

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
