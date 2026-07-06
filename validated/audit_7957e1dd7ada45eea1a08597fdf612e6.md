### Title
Rewards Permanently Frozen in Pool Contract When Pool Balance Below `min_delegation_for_rewards` - (File: `src/pool/pool.cairo`)

### Summary
When the total pool balance is below `min_delegation_for_rewards`, the staking contract unconditionally transfers STRK reward tokens to the pool contract, but the pool contract's `update_rewards_from_staking_contract` silently records a zero increment in the cumulative rewards trace. The transferred STRK tokens become permanently unclaimable by any pool member.

### Finding Description
In `update_pool_rewards` (`src/staking/staking.cairo`), for every pool the staking contract first transfers STRK tokens via `send_rewards_to_delegation_pool`, then calls `pool_dispatcher.update_rewards_from_staking_contract(rewards, pool_balance)`: [1](#0-0) 

Inside `update_rewards_from_staking_contract` (`src/pool/pool.cairo`), the cumulative rewards trace is updated with `last + compute_rewards_per_unit(...)`: [2](#0-1) 

`compute_rewards_per_unit` contains the critical check: [3](#0-2) 

When `total_stake < min_delegation_for_rewards` (e.g., `10^18` for STRK = 1 STRK), the function returns `Zero::zero()`. The cumulative trace is therefore updated as `last + 0 = last` — no change — while the STRK tokens have already been irreversibly transferred to the pool contract. The comment acknowledges this: [4](#0-3) 

Because the cumulative rewards trace is not incremented, `calculate_rewards` will compute zero rewards for those epochs for all pool members. The STRK tokens sitting in the pool contract have no mechanism for recovery.

The `min_delegation_for_rewards` threshold is set in the constructor from `get_token_rewards_config`: [5](#0-4) 

Pool member entry only requires a non-zero amount: [6](#0-5) 

So a pool with total delegated balance below 1 STRK (e.g., a single delegator with 0.5 STRK) is reachable by any unprivileged delegator.

### Impact Explanation
STRK reward tokens transferred to the pool contract when `pool_balance < min_delegation_for_rewards` are permanently frozen. They cannot be claimed by pool members (the cumulative trace records no increment for those epochs), and there is no admin recovery path. This constitutes **permanent freezing of unclaimed yield**.

### Likelihood Explanation
Any unprivileged delegator can create or join a pool with a balance below 1 STRK. A new pool with a single small delegator (e.g., 0.5 STRK) will have its first reward distributions permanently frozen until the pool balance crosses the threshold. The threshold is 1 STRK for STRK pools and `10^(decimals-5)` for BTC pools. While most mature pools exceed this threshold, new or low-activity pools are realistically affected.

### Recommendation
Move the `min_delegation_for_rewards` guard to the staking contract's `update_pool_rewards`, before `send_rewards_to_delegation_pool` is called. If `pool_balance < min_delegation_for_rewards`, skip both the token transfer and the `update_rewards_from_staking_contract` call for that pool. This prevents tokens from being sent to a pool where they cannot be tracked, mirroring the fix pattern from the reference report: the zero-value path should not execute at all when the precondition fails.

### Proof of Concept

1. Staker opens a STRK delegation pool.
2. Delegator calls `enter_delegation_pool` with `amount = 5 * 10^17` (0.5 STRK, below `min_delegation_for_rewards = 10^18`).
3. After K epochs, the attestation contract calls `update_rewards_from_attestation_contract`, which calls `_update_rewards` → `update_pool_rewards`.
4. `send_rewards_to_delegation_pool` transfers, say, `R` STRK to the pool contract.
5. `pool_dispatcher.update_rewards_from_staking_contract(rewards: R, pool_balance: 5*10^17)` is called.
6. Inside, `compute_rewards_per_unit(staking_rewards: R, total_stake: 5*10^17)` checks `5*10^17 < 10^18` → returns `0`.
7. Cumulative trace is updated with `last + 0 = last`.
8. Delegator calls `claim_rewards` → `calculate_rewards` computes `0` for those epochs.
9. `R` STRK tokens remain permanently locked in the pool contract with no recovery path. [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** src/staking/staking.cairo (L1872-1888)
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
                pool_rewards_list.append((pool_contract, pool_rewards));
```

**File:** src/pool/pool.cairo (L62-64)
```text
    pub(crate) const STRK_CONFIG: TokenRewardsConfig = TokenRewardsConfig {
        decimals: 18, min_for_rewards: 10_u128.pow(18), base_value: 10_u128.pow(28),
    };
```

**File:** src/pool/pool.cairo (L191-191)
```text
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
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

**File:** src/pool/pool.cairo (L960-978)
```text
        /// Compute the rewards for the pool trace.
        ///
        /// `staking_rewards` is in `STRK_DECIMALS` decimals.
        /// `total_stake` is in the contract's token decimals.
        /// **Note**: Delegation rewards lost when pool balance is less than
        /// `min_delegation_for_rewards`. The staking contract continues to forward
        /// `pool_rewards` to the pool contract even in this case.
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
