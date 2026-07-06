### Title
Pool Rewards Permanently Frozen When Pool Balance Falls Below `min_delegation_for_rewards` — (File: `src/pool/pool.cairo`)

---

### Summary

When a delegation pool's total balance is below `min_delegation_for_rewards`, the staking contract still physically transfers STRK reward tokens to the pool contract, but the pool's cumulative rewards accounting index (`cumulative_rewards_trace`) is not incremented. The transferred STRK tokens become permanently unclaimable by any pool member, with no recovery path.

---

### Finding Description

The vulnerability spans two files and two functions.

**Step 1 — Staking contract calculates and forwards rewards unconditionally.**

In `update_pool_rewards` (`src/staking/staking.cairo`), for every pool entry in `pools_rewards_data` (which only contains entries where `pool_rewards > 0`), the staking contract:

1. Transfers STRK tokens to the pool via `send_rewards_to_delegation_pool`.
2. Calls `pool_dispatcher.update_rewards_from_staking_contract(rewards: pool_rewards, pool_balance: pool_balance.to_native_amount(:decimals))`. [1](#0-0) 

**Step 2 — Pool contract silently drops the accounting update when balance is too small.**

Inside `update_rewards_from_staking_contract` (`src/pool/pool.cairo`), the cumulative rewards index is updated as `last + compute_rewards_per_unit(...)`. However, `compute_rewards_per_unit` returns **zero** when `total_stake < min_delegation_for_rewards`: [2](#0-1) [3](#0-2) 

The result is `cumulative_rewards_trace.insert(key: epoch, value: last + 0)` — the trace is unchanged. The STRK tokens already transferred in Step 1 are now inside the pool contract but the sigma index that governs `claim_rewards` was never updated.

The code itself documents this discrepancy:

> **Note**: Delegation rewards lost when pool balance is less than `min_delegation_for_rewards`. The staking contract continues to forward `pool_rewards` to the pool contract even in this case. [4](#0-3) 

**Step 3 — No recovery path exists.**

`claim_rewards` in the pool contract computes rewards exclusively from the `cumulative_rewards_trace` sigma values: [5](#0-4) 

`exit_delegation_pool_action` returns only the delegated principal, not rewards. There is no admin sweep or recovery function anywhere in the pool contract. [6](#0-5) 

The `min_delegation_for_rewards` threshold for STRK pools is `10^18` (1 STRK): [7](#0-6) 

---

### Impact Explanation

STRK reward tokens transferred to a pool contract when `pool_balance < min_delegation_for_rewards` are permanently frozen. No pool member, staker, or admin can recover them. This matches the allowed impact: **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

For the freeze to occur, two conditions must hold simultaneously:

1. `pool_balance < min_delegation_for_rewards` (pool has less than 1 STRK delegated).
2. `pool_rewards > 0` after rounding — i.e., `total_rewards × pool_balance / total_stake ≥ 1`.

Condition 2 requires a high reward-to-stake ratio, which limits practical frequency for STRK pools. However, for BTC pools the native-unit conversion (`to_native_amount` with 8 decimals) changes the arithmetic, and the threshold may be crossed more easily depending on the BTC `TokenRewardsConfig`. The condition is also reachable during pool wind-down (most delegators exit, leaving a residual sub-threshold balance across many epochs). Likelihood is **Low-Medium**.

---

### Recommendation

The fix should align the token transfer with the accounting update. Two options:

1. **Skip the transfer when accounting would be zero**: In `update_pool_rewards` (staking.cairo), before calling `send_rewards_to_delegation_pool`, check whether `pool_balance.to_native_amount(:decimals) < pool.min_delegation_for_rewards` and skip both the transfer and the `update_rewards_from_staking_contract` call.

2. **Accumulate untracked rewards for later distribution**: Track a `pending_rewards` accumulator in the pool contract that is credited when `compute_rewards_per_unit` returns zero, and distribute it once the pool balance crosses the threshold.

---

### Proof of Concept

1. Staker S creates a STRK delegation pool.
2. A single delegator D enters with 0.5 STRK (below `min_delegation_for_rewards = 1 STRK`).
3. An attestation or block reward event triggers `_update_rewards` → `calculate_staker_pools_rewards` → `update_pool_rewards`.
4. `pool_rewards_including_commission = total_rewards × 0.5e18 / total_stake`. If this rounds to ≥ 1, `pool_rewards > 0` and the entry is added to `pool_rewards_array`.
5. `send_rewards_to_delegation_pool` transfers `pool_rewards` STRK to the pool contract.
6. `update_rewards_from_staking_contract` is called; `compute_rewards_per_unit` returns 0 because `0.5e18 < 1e18`.
7. `cumulative_rewards_trace` is updated with `last + 0 = last`.
8. D calls `claim_rewards`: `calculate_rewards` computes `(to_sigma - from_sigma) = 0`, returns 0 rewards.
9. The STRK tokens transferred in step 5 are permanently locked in the pool contract.

### Citations

**File:** src/staking/staking.cairo (L1872-1887)
```text
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
```

**File:** src/pool/pool.cairo (L62-64)
```text
    pub(crate) const STRK_CONFIG: TokenRewardsConfig = TokenRewardsConfig {
        decimals: 18, min_for_rewards: 10_u128.pow(18), base_value: 10_u128.pow(28),
    };
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

**File:** src/pool/pool.cairo (L960-966)
```text
        /// Compute the rewards for the pool trace.
        ///
        /// `staking_rewards` is in `STRK_DECIMALS` decimals.
        /// `total_stake` is in the contract's token decimals.
        /// **Note**: Delegation rewards lost when pool balance is less than
        /// `min_delegation_for_rewards`. The staking contract continues to forward
        /// `pool_rewards` to the pool contract even in this case.
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
