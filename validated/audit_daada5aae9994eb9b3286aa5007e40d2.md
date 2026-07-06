### Title
Reward Address Can Add Funds to a Pool Member's Position While Exit Intent Is Active, Enabling Griefing - (File: src/pool/pool.cairo)

### Summary
`add_to_delegation_pool` in `pool.cairo` permits the `reward_address` to inject funds into a pool member's position at any time, including after the pool member has signaled `exit_delegation_pool_intent`. Because the function contains no check for an active exit intent, the reward address can repeatedly add small amounts to the pool member's active balance, forcing the pool member to re-signal exit intent (which resets the exit timer) every time they wish to fully withdraw.

### Finding Description
`add_to_delegation_pool` enforces only two access-control conditions: the caller must be the pool member or their designated `reward_address`, and the staker must be active. It does not verify whether the pool member currently has an active exit intent (`unpool_time.is_some()`). [1](#0-0) 

When a pool member calls `exit_delegation_pool_intent(full_amount)`, their active balance in the epoch-balance trace is reduced to zero and `unpool_amount` is set to `full_amount` with a corresponding `unpool_time`. [2](#0-1) 

Immediately after, the `reward_address` may call `add_to_delegation_pool(pool_member, delta)`. The function transfers `delta` tokens **from the reward address** and calls `increase_member_balance`, which writes a new checkpoint to the pool member's epoch-balance trace, increasing their active balance by `delta`. [3](#0-2) 

The pool member's `unpool_amount` and `unpool_time` are untouched. To exit the newly added `delta`, the pool member must call `exit_delegation_pool_intent` again with the combined amount. This call flows through `remove_from_delegation_pool_intent` in the staking contract, which **recomputes and resets** `unpool_time` to `Time::now() + exit_wait_window`. [4](#0-3) 

The reward address can repeat this pattern indefinitely — each injection just before the exit window closes forces a full timer reset.

### Impact Explanation
The pool member's ability to fully exit is indefinitely delayed. Each time the pool member attempts to include the injected amount in their exit, the exit timer (up to `MAX_EXIT_WAIT_WINDOW` = 12 weeks) is reset from scratch. [5](#0-4) 

This constitutes **griefing with no profit motive but concrete damage to the user**: the pool member's funds are temporarily locked beyond their intended exit window, and they must pay gas for repeated `exit_delegation_pool_intent` calls. This matches the allowed Medium impact: *Griefing with no profit motive but damage to users or protocol*.

### Likelihood Explanation
The `reward_address` is set by the pool member themselves via `change_reward_address`. However:
- The reward address could be a smart contract callable by anyone, making the attack permissionless.
- The reward address could be a key that is later compromised or becomes adversarial.
- The cost to the attacker is real (they spend their own tokens), but a dust amount (e.g., 1 wei above `min_delegation_for_rewards`) suffices to reset the timer.

The pool member can mitigate by calling `change_reward_address`, but this requires awareness of the attack and an on-chain transaction before the next injection.

### Recommendation
Add a check in `add_to_delegation_pool` that rejects calls when the target pool member has an active exit intent:

```cairo
fn add_to_delegation_pool(
    ref self: ContractState, pool_member: ContractAddress, amount: Amount,
) -> Amount {
    self.assert_staker_is_active();
    let pool_member_info = self.internal_pool_member_info(:pool_member);
    // Add this guard:
    assert!(pool_member_info.unpool_time.is_none(), "{}", Error::UNDELEGATE_IN_PROGRESS);
    ...
```

Alternatively, restrict `add_to_delegation_pool` to only the pool member themselves (removing the `reward_address` permission), consistent with how `exit_delegation_pool_intent` is already restricted to the pool member only. [6](#0-5) 

### Proof of Concept

```
1. Pool member delegates 100 STRK.
2. Pool member calls exit_delegation_pool_intent(100 STRK).
   → unpool_amount = 100, unpool_time = now + 1 week, active_balance = 0.
3. Just before unpool_time expires, reward_address calls
   add_to_delegation_pool(pool_member, 1_STRK).
   → active_balance = 1 STRK, unpool_amount = 100 STRK (unchanged).
4. Pool member calls exit_delegation_pool_action → receives 100 STRK.
   The 1 STRK remains locked in the pool.
5. To recover the 1 STRK, pool member calls exit_delegation_pool_intent(1 STRK).
   → remove_from_delegation_pool_intent resets unpool_time = now + 1 week.
6. Reward address repeats step 3. Timer resets again.
   Pool member can never fully exit as long as the reward address keeps injecting dust.
``` [7](#0-6) [8](#0-7)

### Citations

**File:** src/pool/pool.cairo (L221-254)
```text
        fn add_to_delegation_pool(
            ref self: ContractState, pool_member: ContractAddress, amount: Amount,
        ) -> Amount {
            // Asserts.
            self.assert_staker_is_active();
            let pool_member_info = self.internal_pool_member_info(:pool_member);
            let caller_address = get_caller_address();
            assert!(
                caller_address == pool_member || caller_address == pool_member_info.reward_address,
                "{}",
                Error::CALLER_CANNOT_ADD_TO_POOL,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);

            // Transfer funds from the delegator to the staking contract.
            let token_dispatcher = self.token_dispatcher.read();
            let staker_address = self.staker_address.read();
            transfer_from_delegator(pool_member: caller_address, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);

            // Update the pool member's balance checkpoint.
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
            let new_delegated_stake = old_delegated_stake + amount;

            // Emit events.
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake, new_delegated_stake,
                    },
                );

            new_delegated_stake
        }
```

**File:** src/pool/pool.cairo (L256-293)
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

            // Emit events.
            self
                .emit(
                    Events::PoolMemberExitIntent {
                        pool_member, exit_timestamp: unpool_time, amount,
                    },
                );
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake, new_delegated_stake,
                    },
                );
        }
```

**File:** src/staking/staking.cairo (L74-75)
```text
    pub(crate) const DEFAULT_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: WEEK };
    pub(crate) const MAX_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: 12 * WEEK };
```

**File:** src/staking/staking.cairo (L1003-1046)
```text
        fn add_stake_from_pool(
            ref self: ContractState, staker_address: ContractAddress, amount: Amount,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
            let pool_contract = get_caller_address();
            let token_address = self
                .staker_pool_info
                .entry(staker_address)
                .get_pool_token(:pool_contract)
                .expect_with_err(Error::CALLER_IS_NOT_POOL_CONTRACT);
            let decimals = self.get_token_decimals(:token_address);
            let normalized_amount = NormalizedAmountTrait::from_native_amount(:amount, :decimals);

            // Update the staker's staked amount, and add to total_stake.
            let old_delegated_stake = self.get_delegated_balance(:staker_address, :pool_contract);
            let new_delegated_stake = old_delegated_stake + normalized_amount;
            self
                .insert_staker_delegated_balance(
                    :staker_address, :pool_contract, delegated_balance: new_delegated_stake,
                );
            self.add_to_total_stake(:token_address, amount: normalized_amount);

            // Transfer funds from the pool contract to the staking contract.
            // Sufficient approval is a pre-condition.
            let token_dispatcher = IERC20Dispatcher { contract_address: token_address };
            token_dispatcher
                .checked_transfer_from(
                    sender: pool_contract, recipient: get_contract_address(), amount: amount.into(),
                );

            // Emit event.
            self
                .emit(
                    Events::StakeDelegatedBalanceChanged {
                        staker_address,
                        token_address,
                        old_delegated_stake: old_delegated_stake.to_native_amount(:decimals),
                        new_delegated_stake: new_delegated_stake.to_native_amount(:decimals),
                    },
                );
        }
```

**File:** src/staking/staking.cairo (L1048-1111)
```text
        fn remove_from_delegation_pool_intent(
            ref self: ContractState,
            staker_address: ContractAddress,
            identifier: felt252,
            amount: Amount,
        ) -> Timestamp {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_info = self.internal_staker_info(:staker_address);
            let pool_contract = get_caller_address();
            let token_address = self
                .staker_pool_info
                .entry(staker_address)
                .get_pool_token(:pool_contract)
                .expect_with_err(Error::CALLER_IS_NOT_POOL_CONTRACT);
            let decimals = self.get_token_decimals(:token_address);
            let normalized_amount = NormalizedAmountTrait::from_native_amount(:amount, :decimals);

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

            self
                .emit(
                    Events::RemoveFromDelegationPoolIntent {
                        staker_address,
                        pool_contract,
                        token_address,
                        identifier,
                        old_intent_amount: old_intent_amount.to_native_amount(:decimals),
                        new_intent_amount: amount,
                    },
                );
            // If the staker is in the process of unstaking (intent called),
            // an event indicating the staked amount (own and delegated) to be zero
            // had already been emitted, thus unneeded now.
            if staker_info.unstake_time.is_none() {
                self
                    .emit(
                        Events::StakeDelegatedBalanceChanged {
                            staker_address,
                            token_address,
                            old_delegated_stake: old_delegated_stake.to_native_amount(:decimals),
                            new_delegated_stake: new_delegated_stake.to_native_amount(:decimals),
                        },
                    );
            }
            self.get_pool_exit_intent(:undelegate_intent_key).unpool_time
        }
```

**File:** src/pool/interface.cairo (L79-85)
```text
    /// #### Access control:
    /// Only the pool member address.
    ///
    /// #### Internal calls:
    /// - [`staking::staking::interface::IStakingPool::remove_from_delegation_pool_intent`]
    /// - [`staking::staking::interface::IStaking::get_current_epoch`]
    fn exit_delegation_pool_intent(ref self: TContractState, amount: Amount);
```
