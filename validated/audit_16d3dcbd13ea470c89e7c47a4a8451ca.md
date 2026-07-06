### Title
Permanent Freezing of Pool Rewards When Pool Balance Falls Below `min_delegation_for_rewards` — (File: `src/pool/pool.cairo`)

---

### Summary

The Starknet Staking pool contract permanently locks STRK reward tokens when the pool's total delegated balance falls below `min_delegation_for_rewards`. The staking contract unconditionally transfers reward tokens to the pool contract, but the pool contract's accounting (`cumulative_rewards_trace`) is not updated in this case, making those tokens permanently unclaimable by any pool member.

---

### Finding Description

In `src/staking/staking.cairo`, `update_pool_rewards` always calls `send_rewards_to_delegation_pool` (transferring STRK tokens to the pool contract) and then calls `pool_dispatcher.update_rewards_from_staking_contract(rewards, pool_balance)` regardless of whether `pool_balance` is above or below the minimum threshold. [1](#0-0) 

Inside the pool contract, `update_rewards_from_staking_contract` calls `compute_rewards_per_unit`, which returns **zero** when `total_stake < min_delegation_for_rewards`: [2](#0-1) [3](#0-2) 

When `compute_rewards_per_unit` returns zero, the `cumulative_rewards_trace` is updated with `last + 0`, i.e., no change. The STRK tokens have already been transferred to the pool contract's balance, but the sigma (cumulative rewards per unit) is never incremented. Since `calculate_rewards` for any pool member computes `amount * (sigma_to - sigma_from) / base_value`, and the sigma delta is zero for those epochs, pool members can never claim those rewards.

The code comment in `pool.cairo` explicitly acknowledges this: [4](#0-3) 

There is no recovery function in the pool contract to retrieve these locked tokens. `claim_rewards`, `exit_delegation_pool_action`, and `set_staker_removed` all operate on tracked balances and sigma values — none can recover tokens that were deposited but never accounted for in the trace.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

STRK reward tokens transferred to the pool contract when `pool_balance < min_delegation_for_rewards` are permanently locked. No pool member, staker, or governance role can recover them. The pool contract has no sweep or rescue function. The tokens accumulate in the pool contract's ERC-20 balance but are forever inaccessible.

For STRK pools, `min_delegation_for_rewards = 10^18` (1 STRK). [5](#0-4) 

---

### Likelihood Explanation

**Medium.** The scenario arises naturally when:

1. A pool's total delegated balance drops below 1 STRK — e.g., most delegators exit via `exit_delegation_pool_intent` / `exit_delegation_pool_action`, leaving only a small residual balance.
2. A staker creates a pool and only a single small delegator (< 1 STRK) joins before rewards are distributed.

No privileged access is required. Any delegator can trigger this by entering a pool with a small amount when no other delegators are present. The `enter_delegation_pool` function enforces no minimum delegation amount relative to `min_delegation_for_rewards`.

---

### Recommendation

In `update_pool_rewards` (staking contract), check whether `pool_balance >= min_delegation_for_rewards` before transferring rewards to the pool. If the pool balance is below the threshold, redirect those rewards to the staker's reward address (as commission) or skip the transfer entirely and do not call `update_rewards_from_staking_contract`. This prevents STRK tokens from being sent to the pool contract when they cannot be tracked or claimed.

Alternatively, in `update_rewards_from_staking_contract` (pool contract), if `compute_rewards_per_unit` returns zero, the pool contract should return the `rewards` amount back to the staking contract rather than silently accepting tokens it cannot distribute.

---

### Proof of Concept

1. Staker S creates a pool with commission 10%.
2. Delegator D enters the pool with 0.5 STRK (< `min_delegation_for_rewards = 1 STRK`). Total pool balance = 0.5 STRK.
3. The sequencer calls `update_rewards` for staker S.
4. In `_update_rewards`, `calculate_staker_pools_rewards` computes `pool_rewards = X STRK` (proportional to pool's share of total stake).
5. `update_pool_rewards` calls `send_rewards_to_delegation_pool`, transferring X STRK to the pool contract.
6. `pool_dispatcher.update_rewards_from_staking_contract(rewards: X, pool_balance: 0.5 STRK)` is called.
7. Inside the pool, `compute_rewards_per_unit` returns 0 because `0.5 STRK < 1 STRK`.
8. `cumulative_rewards_trace` is updated with `last + 0` — no change.
9. Delegator D calls `claim_rewards` — receives 0 because sigma delta is 0 for that epoch.
10. X STRK tokens are permanently locked in the pool contract's balance. [6](#0-5) [7](#0-6)

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

**File:** src/staking/staking.cairo (L2348-2365)
```text
            // Update reward supplier.
            let staker_rewards = staker_own_rewards + commission_rewards;
            // Update total rewards.
            reward_supplier_dispatcher
                .update_unclaimed_rewards_from_staking_contract(
                    rewards: staker_rewards + total_pools_rewards,
                );
            // Claim pools rewards.
            claim_from_reward_supplier(
                :reward_supplier_dispatcher,
                amount: total_pools_rewards,
                token_dispatcher: strk_token_dispatcher(),
            );
            // Update staker rewards.
            staker_info.unclaimed_rewards_own += staker_rewards;

            // Update pools rewards.
            let pool_rewards_list = self.update_pool_rewards(:staker_address, :pools_rewards_data);
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
