### Title
STRK Rewards Transferred to Pool Are Permanently Frozen When Pool Balance Is Below `min_delegation_for_rewards` — (File: `src/pool/pool.cairo`)

---

### Summary

In `update_pool_rewards` (`staking.cairo`), STRK reward tokens are unconditionally transferred to the pool contract whenever `pool_rewards > 0`. However, inside `update_rewards_from_staking_contract` (`pool.cairo`), `compute_rewards_per_unit` silently returns `0` when `pool_balance < min_delegation_for_rewards`, recording nothing in the `cumulative_rewards_trace`. The transferred STRK tokens have no claim path and are permanently frozen in the pool contract.

---

### Finding Description

**Step 1 — Staking contract calculates and sends pool rewards unconditionally.**

In `calculate_staker_pools_rewards`, the staking contract computes `pool_rewards` proportionally to the pool's delegated balance. If `pool_rewards > 0`, the pool is appended to `pool_rewards_array` regardless of whether the pool balance meets the minimum threshold: [1](#0-0) 

Then in `update_pool_rewards`, for every pool in that array, `send_rewards_to_delegation_pool` transfers STRK tokens to the pool contract **unconditionally**, followed by a call to `update_rewards_from_staking_contract`: [2](#0-1) 

**Step 2 — Pool contract records zero rewards per unit when balance is below threshold.**

Inside `update_rewards_from_staking_contract`, `compute_rewards_per_unit` is called. When `total_stake < min_delegation_for_rewards`, it returns `0`: [3](#0-2) 

The `cumulative_rewards_trace` is still updated, but with the same value as the previous entry (delta = 0): [4](#0-3) 

The comment in `compute_rewards_per_unit` explicitly acknowledges this mismatch: *"Delegation rewards lost when pool balance is less than `min_delegation_for_rewards`. The staking contract continues to forward `pool_rewards` to the pool contract even in this case."*

**Step 3 — No recovery path exists.**

`claim_rewards` derives payouts exclusively from the `cumulative_rewards_trace` (which recorded 0), so delegators receive nothing: [5](#0-4) 

`exit_delegation_pool_action` returns only the delegated principal (`unpool_amount`), not reward tokens: [6](#0-5) 

There is no admin sweep or recovery function in the pool contract. The STRK tokens are permanently locked.

---

### Impact Explanation

**Permanent freezing of unclaimed yield.** Every time `update_rewards` or `update_rewards_from_attestation_contract` is called while a pool's total delegated balance is below `min_delegation_for_rewards` (e.g., `10^18` wei = 1 STRK for STRK pools), the proportional STRK reward share for that pool is transferred into the pool contract and becomes irrecoverable. The amount accumulates with each reward cycle.

---

### Likelihood Explanation

Any pool whose total delegated balance is below `min_delegation_for_rewards` triggers this. For STRK pools, `min_delegation_for_rewards = 10^18` (1 STRK): [7](#0-6) 

`enter_delegation_pool` accepts any non-zero amount with no minimum enforcement: [8](#0-7) 

A single delegator contributing 0.5 STRK to an otherwise-empty pool is sufficient. With a 1000 STRK total stake and 100 STRK epoch rewards, that pool would receive ≈0.05 STRK per reward cycle, all permanently frozen. This scenario is reachable by any unprivileged delegator.

---

### Recommendation

In `update_pool_rewards` (or in `calculate_staker_pools_rewards`), skip sending rewards to a pool when its native balance is below `min_delegation_for_rewards`. Alternatively, redirect those rewards to the staker's reward address rather than transferring them to the pool contract where they cannot be claimed.

---

### Proof of Concept

1. Deploy the system with a staker and a STRK pool.
2. A delegator calls `enter_delegation_pool` with `amount = 5 * 10^17` (0.5 STRK, below `min_delegation_for_rewards = 10^18`).
3. Advance K epochs so the balance becomes effective.
4. Call `update_rewards` (or trigger attestation). The staking contract computes `pool_rewards > 0` (proportional to 0.5 STRK / total_stake × total_rewards) and transfers that STRK to the pool contract.
5. Inside `update_rewards_from_staking_contract`, `compute_rewards_per_unit` returns `0` because `5 * 10^17 < 10^18`.
6. The `cumulative_rewards_trace` records no increase.
7. The delegator calls `claim_rewards` → receives `0`.
8. The delegator calls `exit_delegation_pool_intent` + `exit_delegation_pool_action` → receives only their 0.5 STRK principal.
9. The STRK reward tokens remain in the pool contract with no claim path, confirmed by checking the pool's STRK token balance exceeds the sum of all delegated principals.

### Citations

**File:** src/staking/staking.cairo (L1865-1891)
```text
        fn update_pool_rewards(
            ref self: ContractState,
            staker_address: ContractAddress,
            pools_rewards_data: Array<(ContractAddress, ContractAddress, NormalizedAmount, Amount)>,
        ) -> Array<(ContractAddress, Amount)> {
            let mut pool_rewards_list = array![];
            let strk_token_dispatcher = strk_token_dispatcher();
            for (pool_contract, token_address, pool_balance, pool_rewards) in pools_rewards_data {
                let pool_dispatcher = IPoolDispatcher { contract_address: pool_contract };
                // Rewards are always in STRK.
                self
                    .send_rewards_to_delegation_pool(
                        :staker_address,
                        pool_address: pool_contract,
                        amount: pool_rewards,
                        token_dispatcher: strk_token_dispatcher,
                    );
                let decimals = self.get_token_decimals(:token_address);
                pool_dispatcher
                    .update_rewards_from_staking_contract(
                        rewards: pool_rewards,
                        pool_balance: pool_balance.to_native_amount(:decimals),
                    );
                pool_rewards_list.append((pool_contract, pool_rewards));
            }
            pool_rewards_list
        }
```

**File:** src/staking/staking.cairo (L1979-1999)
```text
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
                if pool_rewards.is_non_zero() {
                    pool_rewards_array
                        .append(
                            (pool_contract, token_address, pool_balance_curr_epoch, pool_rewards),
                        );
                }
```

**File:** src/pool/pool.cairo (L62-64)
```text
    pub(crate) const STRK_CONFIG: TokenRewardsConfig = TokenRewardsConfig {
        decimals: 18, min_for_rewards: 10_u128.pow(18), base_value: 10_u128.pow(28),
    };
```

**File:** src/pool/pool.cairo (L182-219)
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

            self.set_member_balance(:pool_member, :amount);

            // Create the pool member record.
            self
                .pool_member_info
                .write(pool_member, VInternalPoolMemberInfoTrait::new_latest(:reward_address));

            // Emit events.
            self
                .emit(
                    Events::NewPoolMember { pool_member, staker_address, reward_address, amount },
                );
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake: Zero::zero(), new_delegated_stake: amount,
                    },
                );
        }
```

**File:** src/pool/pool.cairo (L295-333)
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

            // Emit event.
            self
                .emit(
                    Events::PoolMemberExitAction {
                        pool_member, unpool_amount: pool_member_info.unpool_amount,
                    },
                );

            // Perform removal action in the staking contract, receiving funds if needed.
            // Note that if the intent was done after the staker was removed (unstake_action),
            // the funds will already be in the pool contract, and the following call will do
            // nothing.
            let staking_pool_dispatcher = self.staking_pool_dispatcher.read();
            staking_pool_dispatcher
                .remove_from_delegation_pool_action(identifier: pool_member.into());

            let unpool_amount = pool_member_info.unpool_amount;
            pool_member_info.unpool_amount = Zero::zero();
            pool_member_info.unpool_time = Option::None;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer delegated amount to the pool member.
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());

            unpool_amount
        }
```

**File:** src/pool/pool.cairo (L335-377)
```text
        fn claim_rewards(ref self: ContractState, pool_member: ContractAddress) -> Amount {
            // Asserts.
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let caller_address = get_caller_address();
            let reward_address = pool_member_info.reward_address;
            assert!(
                caller_address == pool_member || caller_address == reward_address,
                "{}",
                Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );

            let until_checkpoint = self.get_current_checkpoint(:pool_member);

            // Calculate rewards and update entry_to_claim_from.
            let (mut rewards, updated_entry_to_claim_from) = self
                .calculate_rewards(
                    :pool_member,
                    from_checkpoint: pool_member_info.reward_checkpoint,
                    :until_checkpoint,
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
            rewards += pool_member_info._unclaimed_rewards_from_v0;
            pool_member_info._unclaimed_rewards_from_v0 = Zero::zero();
            pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
            pool_member_info.reward_checkpoint = until_checkpoint;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());

            // Emit event.
            self
                .emit(
                    Events::PoolMemberRewardClaimed {
                        pool_member, reward_address, amount: rewards,
                    },
                );

            rewards
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
