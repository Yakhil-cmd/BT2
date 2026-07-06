### Title
Pool Rewards Permanently Silenced When Delegated Balance Drops Below `min_delegation_for_rewards` — (`src/pool/pool.cairo`)

### Summary

A large delegator can intentionally exit a small delegation pool, leaving its total delegated balance below the `min_delegation_for_rewards` threshold. When this happens, `compute_rewards_per_unit` silently returns zero, causing all pool rewards for every affected epoch to be permanently unclaimable by the remaining pool members. The attacker profits by concentrating their stake in a preferred pool.

### Finding Description

The pool contract's `compute_rewards_per_unit` function contains a hard floor check:

```cairo
fn compute_rewards_per_unit(
    self: @ContractState, staking_rewards: Amount, total_stake: Amount,
) -> Index {
    if total_stake < self.min_delegation_for_rewards.read() {
        return Zero::zero();
    }
    ...
}
``` [1](#0-0) 

For STRK pools, `min_delegation_for_rewards` is set to `10^18` (1 STRK) from `STRK_CONFIG`:

```cairo
pub(crate) const STRK_CONFIG: TokenRewardsConfig = TokenRewardsConfig {
    decimals: 18, min_for_rewards: 10_u128.pow(18), base_value: 10_u128.pow(28),
};
``` [2](#0-1) 

This value is written to storage in the constructor: [3](#0-2) 

`compute_rewards_per_unit` is called inside `update_rewards_from_staking_contract`, which updates the cumulative rewards trace used by all pool members to calculate their claimable yield: [4](#0-3) 

When `compute_rewards_per_unit` returns zero, the cumulative rewards trace does not advance for that epoch. Every pool member's `calculate_rewards` call will compute zero rewards for that epoch — permanently, since the trace is append-only and past epochs cannot be retroactively corrected. [5](#0-4) 

The entry point for the attack is `exit_delegation_pool_intent`, which is callable by any pool member with no minimum-remaining-balance guard: [6](#0-5) 

There is no check anywhere in `exit_delegation_pool_intent` or in the staking contract's `remove_from_delegation_pool_intent` that prevents the pool's remaining delegated balance from falling below `min_delegation_for_rewards`. The staking contract simply decrements the delegated balance: [7](#0-6) 

After exiting, the attacker can call `switch_delegation_pool` to redirect their stake to a preferred pool, concentrating rewards there: [8](#0-7) 

### Impact Explanation

When the pool balance drops below 1 STRK, `compute_rewards_per_unit` returns zero for every subsequent epoch until the balance recovers. The rewards forwarded by the staking contract for those epochs are never credited to pool members in the cumulative trace. Because the trace is append-only and epoch-indexed, those reward slots are permanently zero — remaining pool members suffer **permanent freezing of unclaimed yield** for every epoch the pool stays below the threshold.

This matches the allowed High impact: *"Permanent freezing of unclaimed yield or unclaimed royalties."*

### Likelihood Explanation

- No privileged role is required; any pool member can call `exit_delegation_pool_intent`.
- The attack is profitable: the attacker moves their stake to a preferred pool, increasing their own reward share.
- Small pools (e.g., newly created pools or pools with few delegators) are realistic targets; a pool with 1.5 STRK total is bricked by a single 0.6 STRK exit.
- The `K = 2` epoch delay on balance changes means the attacker has a predictable window to execute the exit before the next reward distribution. [9](#0-8) 

### Recommendation

1. **Guard exits against under-threshold residuals**: In `exit_delegation_pool_intent` (or in `remove_from_delegation_pool_intent` on the staking contract), assert that the remaining delegated balance after the exit is either zero or `>= min_delegation_for_rewards`. A partial exit that would leave a non-zero but sub-threshold balance should be rejected.

2. **Redistribute silenced rewards**: Instead of silently returning zero in `compute_rewards_per_unit`, accumulate the untracked rewards and either return them to the staking contract or hold them for redistribution when the pool balance recovers.

3. **Emit an observable event**: At minimum, emit a warning event when rewards are silenced due to sub-threshold balance, so off-chain monitoring can detect the condition.

### Proof of Concept

1. Pool A (STRK) has 1.5 STRK delegated: 1.0 STRK from attacker, 0.5 STRK from victim.
2. Attacker calls `exit_delegation_pool_intent(amount: 1_000_000_000_000_000_001)` — leaves Pool A with `0.5 STRK - 1 wei < 10^18`.
3. Staking contract calls `update_rewards_from_staking_contract(rewards: R, pool_balance: <10^18)` on Pool A.
4. `compute_rewards_per_unit` returns `Zero::zero()` → cumulative trace unchanged → victim earns 0 for this epoch.
5. Attacker calls `switch_delegation_pool(to_staker: preferred_staker, to_pool: Pool B, amount: ...)` — their 1 STRK now earns full rewards in Pool B.
6. Victim's yield for every epoch Pool A stays below 1 STRK is permanently lost.

### Citations

**File:** src/pool/pool.cairo (L62-64)
```text
    pub(crate) const STRK_CONFIG: TokenRewardsConfig = TokenRewardsConfig {
        decimals: 18, min_for_rewards: 10_u128.pow(18), base_value: 10_u128.pow(28),
    };
```

**File:** src/pool/pool.cairo (L164-166)
```text
        let config = get_token_rewards_config(:token_address);
        self.min_delegation_for_rewards.write(config.min_for_rewards);
        self.staking_rewards_base_value.write(config.base_value);
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

**File:** src/pool/pool.cairo (L379-429)
```text
        fn switch_delegation_pool(
            ref self: ContractState,
            to_staker: ContractAddress,
            to_pool: ContractAddress,
            amount: Amount,
        ) -> Amount {
            // Asserts.
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            assert!(
                pool_member_info.unpool_time.is_some(),
                "{}",
                GenericError::MISSING_UNDELEGATE_INTENT,
            );
            assert!(amount <= pool_member_info.unpool_amount, "{}", GenericError::AMOUNT_TOO_HIGH);
            let reward_address = pool_member_info.reward_address;

            // Update pool_member_info and write to storage.
            pool_member_info.unpool_amount -= amount;
            if pool_member_info.unpool_amount.is_zero() {
                // unpool_amount is zero, clear unpool_time.
                pool_member_info.unpool_time = Option::None;
            }
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Serialize the switch pool data and invoke the staking contract to switch pool.
            let switch_pool_data = SwitchPoolData { pool_member, reward_address };
            let mut serialized_data = array![];
            switch_pool_data.serialize(ref output: serialized_data);
            self
                .staking_pool_dispatcher
                .read()
                .switch_staking_delegation_pool(
                    :to_staker,
                    :to_pool,
                    switched_amount: amount,
                    data: serialized_data.span(),
                    identifier: pool_member.into(),
                );

            // Emit event.
            self
                .emit(
                    Events::SwitchDelegationPool {
                        pool_member, new_delegation_pool: to_pool, amount,
                    },
                );

            pool_member_info.unpool_amount
        }
```

**File:** src/pool/pool.cairo (L569-587)
```text
        fn update_rewards_from_staking_contract(
            ref self: ContractState, rewards: Amount, pool_balance: Amount,
        ) {
            self.assert_caller_is_staking_contract();

            // `rewards_info` is initialized in the constructor or in the upgrade proccess,
            // so unwrapping should be safe.
            let (_, last) = self.cumulative_rewards_trace.last().unwrap();
            self
                .cumulative_rewards_trace
                .insert(
                    key: self.get_current_epoch(),
                    value: last
                        + self
                            .compute_rewards_per_unit(
                                staking_rewards: rewards, total_stake: pool_balance,
                            ),
                );
        }
```

**File:** src/pool/pool.cairo (L837-888)
```text
        fn calculate_rewards(
            self: @ContractState,
            pool_member: ContractAddress,
            from_checkpoint: PoolMemberCheckpoint,
            until_checkpoint: PoolMemberCheckpoint,
            mut entry_to_claim_from: VecIndex,
        ) -> (Amount, VecIndex) {
            let pool_member_trace = self.pool_member_epoch_balance.entry(pool_member);
            // Note: `until_epoch` is the current epoch.
            let until_epoch = until_checkpoint.epoch();

            let mut rewards = 0;

            let pool_member_trace_length = pool_member_trace.length();

            let mut from_sigma = self.find_sigma(from_checkpoint, curr_epoch: until_epoch);
            let mut from_balance = from_checkpoint.balance();

            let base_value = self.staking_rewards_base_value.read();

            // **Note**: The loop iterates over the balance changes in the pool member's balance
            // trace. This loop is unbounded but unlikely to exceed gas limits.
            while entry_to_claim_from < pool_member_trace_length {
                let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
                // If the balance change is after `until_epoch` (and therefore does not affect
                // the current reward computation), exit the loop.
                if pool_member_checkpoint.epoch() >= until_epoch {
                    break;
                }

                // Compute rewards from (inclusive) the previous balance change (or from
                // `from_checkpoint`) to (exclusive) the current entry.
                let to_sigma = self.find_sigma(pool_member_checkpoint, curr_epoch: until_epoch);
                rewards +=
                    compute_rewards_rounded_down(
                        amount: from_balance, interest: to_sigma - from_sigma, :base_value,
                    );
                from_sigma = to_sigma;
                from_balance = pool_member_checkpoint.balance();
                entry_to_claim_from += 1;
            }

            // Compute the remaining rewards from (inclusive) the last visited balance change in
            // `pool_member_trace` (or from `from_checkpoint`) to (exclusive) `until_checkpoint`.
            let to_sigma = self.find_sigma(until_checkpoint, curr_epoch: until_epoch);
            rewards +=
                compute_rewards_rounded_down(
                    amount: from_balance, interest: to_sigma - from_sigma, :base_value,
                );

            (rewards, entry_to_claim_from)
        }
```

**File:** src/pool/pool.cairo (L967-978)
```text
        fn compute_rewards_per_unit(
            self: @ContractState, staking_rewards: Amount, total_stake: Amount,
        ) -> Index {
            // Return zero if the total stake is too small, to avoid overflow below.
            if total_stake < self.min_delegation_for_rewards.read() {
                return Zero::zero();
            }
            mul_wide_and_div(
                lhs: staking_rewards, rhs: self.staking_rewards_base_value.read(), div: total_stake,
            )
                .expect_with_err(err: InternalError::REWARDS_COMPUTATION_OVERFLOW)
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

**File:** src/constants.cairo (L13-13)
```text
pub(crate) const K: u8 = 2;
```
