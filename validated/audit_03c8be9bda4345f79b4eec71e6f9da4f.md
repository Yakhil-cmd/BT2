### Title
Delegation Rewards Permanently Frozen in Pool Contract When Pool Balance Is Below `min_delegation_for_rewards` - (File: src/pool/pool.cairo)

### Summary

When a pool's total delegated balance is below `min_delegation_for_rewards` (10^18 fractions = 1 STRK for STRK pools), `compute_rewards_per_unit` returns zero and the `cumulative_rewards_trace` is not incremented. However, the staking contract has **already transferred** the pool rewards tokens to the pool contract before this check occurs. These rewards are permanently frozen in the pool contract with no recovery mechanism.

### Finding Description

The pool contract tracks accumulated rewards per unit of stake in `cumulative_rewards_trace` — a MasterChef-style sigma accumulator. Each time the staking contract distributes rewards, it calls `update_rewards_from_staking_contract`, which appends a new entry to the trace via `compute_rewards_per_unit`.

`compute_rewards_per_unit` contains an explicit guard:

```cairo
fn compute_rewards_per_unit(
    self: @ContractState, staking_rewards: Amount, total_stake: Amount,
) -> Index {
    // Return zero if the total stake is too small, to avoid overflow below.
    if total_stake < self.min_delegation_for_rewards.read() {
        return Zero::zero();
    }
    ...
}
``` [1](#0-0) 

When this guard fires, the trace entry is inserted with the **same value as the previous entry** — the sigma does not advance. Delegators computing their rewards via `calculate_rewards` will therefore see zero interest for that epoch, regardless of how many reward tokens were deposited.

The critical ordering problem is in `update_pool_rewards` in the staking contract:

```cairo
// Rewards are always in STRK.
self.send_rewards_to_delegation_pool(
    :staker_address,
    pool_address: pool_contract,
    amount: pool_rewards,
    token_dispatcher: strk_token_dispatcher,
);
...
pool_dispatcher
    .update_rewards_from_staking_contract(
        rewards: pool_rewards,
        pool_balance: pool_balance.to_native_amount(:decimals),
    );
``` [2](#0-1) 

The token transfer happens **before** `update_rewards_from_staking_contract` is called. If `pool_balance < min_delegation_for_rewards`, the tokens land in the pool contract but the sigma trace is not updated. The pool contract has no sweep or recovery function, so those tokens are permanently locked.

The code itself acknowledges this in a comment on `compute_rewards_per_unit`:

> **Note**: Delegation rewards lost when pool balance is less than `min_delegation_for_rewards`. The staking contract continues to forward `pool_rewards` to the pool contract even in this case. [3](#0-2) 

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Any STRK reward tokens forwarded to a pool contract while its total delegated balance is below `min_delegation_for_rewards` (1 STRK) are irrecoverably locked. The pool contract exposes no admin withdrawal, no rescue function, and no path through `claim_rewards` that would distribute tokens whose corresponding sigma increment is zero. The `cumulative_rewards_trace` is append-only and never decremented.

### Likelihood Explanation

**Medium.** The scenario is reachable without any privileged access:

1. A staker opens a STRK delegation pool (`set_open_for_delegation`).
2. A delegator enters with any non-zero amount below 1 STRK (the only check is `amount.is_non_zero()`).
3. The pool's total delegated balance is now below `min_delegation_for_rewards`.
4. On the next `update_rewards` call, `calculate_staker_pools_rewards` computes a non-zero `pool_rewards` (proportional to `pool_balance / total_stake`), appends the pool to `pool_rewards_array`, and `update_pool_rewards` transfers those tokens to the pool contract.
5. `compute_rewards_per_unit` returns 0; the sigma trace is unchanged; the tokens are frozen.

This also occurs if existing delegators withdraw enough stake to push the pool balance below the threshold, affecting the remaining delegators.

### Recommendation

In `update_pool_rewards` (or in `calculate_staker_pools_rewards`), skip forwarding rewards to a pool whose `pool_balance < min_delegation_for_rewards`. Concretely, before calling `send_rewards_to_delegation_pool`, check:

```cairo
if pool_balance.to_native_amount(:decimals) < pool_dispatcher.get_min_delegation_for_rewards() {
    continue; // do not send; rewards remain in reward_supplier
}
```

Alternatively, expose a governance-controlled sweep function on the pool contract so that any accidentally deposited tokens can be recovered.

### Proof of Concept

1. Deploy the system with `min_stake = 1 STRK` (or any value where a pool balance of 0.5 STRK is a meaningful fraction of total stake).
2. Staker stakes 0.5 STRK own balance; opens a STRK delegation pool.
3. Delegator calls `enter_delegation_pool` with `amount = 0.5 STRK` (passes the `is_non_zero` check).
4. Pool's total delegated balance = 0.5 STRK < `min_delegation_for_rewards` = 1 STRK.
5. Advance to consensus rewards epoch; call `update_rewards`.
6. Inside `calculate_staker_pools_rewards`: `pool_balance_curr_epoch = 0.5 STRK`, `total_stake = 1 STRK`, `pool_rewards = total_rewards × 0.5` — non-zero, pool is appended to `pool_rewards_array`.
7. `send_rewards_to_delegation_pool` transfers `pool_rewards` STRK tokens to the pool contract.
8. `update_rewards_from_staking_contract` is called; `compute_rewards_per_unit(pool_rewards, 0.5 STRK)` returns 0 because `0.5 STRK < min_delegation_for_rewards`.
9. `cumulative_rewards_trace` receives a new entry equal to the previous entry (no increment).
10. Delegator calls `claim_rewards` → receives 0 STRK.
11. The `pool_rewards` tokens sit in the pool contract with no mechanism to extract them. [4](#0-3) [1](#0-0) [5](#0-4) [6](#0-5)

### Citations

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
