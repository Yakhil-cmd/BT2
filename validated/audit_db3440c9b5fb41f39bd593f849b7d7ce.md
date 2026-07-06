### Title
Rewards Permanently Locked in Pool Contract When Pool Balance Falls Below `min_delegation_for_rewards` - (File: `src/pool/pool.cairo`)

### Summary

When the total pool balance is below `min_delegation_for_rewards`, the staking contract still calculates non-zero pool rewards and physically transfers STRK tokens to the pool contract, but the pool's `compute_rewards_per_unit` returns zero, making those tokens permanently unclaimable by any pool member.

### Finding Description

The staking contract's `_update_rewards` → `calculate_staker_pools_rewards` → `update_pool_rewards` pipeline calculates pool rewards proportional to `pool_balance_curr_epoch` and sends them to the pool contract unconditionally (as long as `pool_rewards > 0`).

In `calculate_staker_pools_rewards` (`src/staking/staking.cairo`):

```cairo
let pool_rewards_including_commission = if total_stake.is_non_zero() {
    mul_wide_and_div(
        lhs: total_rewards,
        rhs: pool_balance_curr_epoch.to_amount_18_decimals(),
        div: total_stake.to_amount_18_decimals(),
    )...
};
...
if pool_rewards.is_non_zero() {
    pool_rewards_array.append((pool_contract, token_address, pool_balance_curr_epoch, pool_rewards));
}
``` [1](#0-0) 

In `update_pool_rewards`, the staking contract physically transfers `pool_rewards` STRK to the pool contract, then calls `update_rewards_from_staking_contract`: [2](#0-1) 

Inside the pool, `update_rewards_from_staking_contract` calls `compute_rewards_per_unit`: [3](#0-2) 

And `compute_rewards_per_unit` returns **zero** when `total_stake < min_delegation_for_rewards`: [4](#0-3) 

The production code itself documents this behavior:

> **Note**: Delegation rewards lost when pool balance is less than `min_delegation_for_rewards`. The staking contract continues to forward `pool_rewards` to the pool contract even in this case. [5](#0-4) 

The cumulative rewards trace is updated with a zero increment, so no pool member can ever claim the transferred tokens. There is no recovery or sweep mechanism in the pool contract.

The thresholds are:
- **STRK pool**: `min_delegation_for_rewards = 10^18` (1 STRK in fractions) — `STRK_CONFIG`
- **BTC pool (8 decimals)**: `min_delegation_for_rewards = 10^3 = 1000 satoshis`
- **BTC pool (18 decimals)**: `min_delegation_for_rewards = 10^13` [6](#0-5) 

### Impact Explanation

STRK tokens are physically transferred to the pool contract via `checked_transfer` but can never be claimed by pool members because the cumulative rewards index is not incremented. The tokens are permanently frozen in the pool contract with no admin sweep, no recovery path, and no expiry mechanism. This constitutes **permanent freezing of unclaimed yield**.

### Likelihood Explanation

Any delegator can enter a pool with an amount below `min_delegation_for_rewards` — there is no enforced minimum delegation amount at pool entry. For a STRK pool, delegating less than 1 STRK triggers the condition. For a BTC pool with 8 decimals, delegating fewer than 1000 satoshis triggers it. New pools with a single small delegator are a realistic scenario. The condition persists across every block/epoch until the pool balance grows above the threshold, accumulating locked rewards over time.

### Recommendation

The staking contract should skip sending rewards to the pool (and skip calling `update_rewards_from_staking_contract`) when `pool_balance.to_native_amount(decimals) < pool.min_delegation_for_rewards`. Alternatively, the pool contract should track "unindexed rewards" separately and allow them to be redistributed once the pool balance crosses the threshold, or returned to the reward supplier.

### Proof of Concept

1. Staker stakes and opens a STRK delegation pool.
2. Delegator enters the pool with `5 * 10^17` fractions (0.5 STRK < `min_delegation_for_rewards = 10^18`).
3. Staker attests / `update_rewards` is called.
4. `calculate_staker_pools_rewards` computes `pool_rewards > 0` (since `pool_balance > 0`).
5. `send_rewards_to_delegation_pool` transfers `pool_rewards` STRK to the pool contract.
6. `update_rewards_from_staking_contract` is called; `compute_rewards_per_unit` returns 0 because `5 * 10^17 < 10^18`.
7. Cumulative rewards trace is incremented by 0.
8. Delegator calls `claim_rewards` → receives 0.
9. Pool contract STRK balance > 0 permanently, with no recovery path.

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

**File:** src/staking/staking.cairo (L1979-1998)
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
```

**File:** src/pool/pool.cairo (L62-64)
```text
    pub(crate) const STRK_CONFIG: TokenRewardsConfig = TokenRewardsConfig {
        decimals: 18, min_for_rewards: 10_u128.pow(18), base_value: 10_u128.pow(28),
    };
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
