### Title
Pool Rewards Permanently Frozen When Pool Balance Falls Below `min_delegation_for_rewards` — (`src/pool/pool.cairo`)

---

### Summary

When a pool's total delegated balance is below `min_delegation_for_rewards`, the staking contract still calculates and transfers STRK reward tokens to the pool contract, but the pool contract's `compute_rewards_per_unit` silently returns zero. The cumulative rewards trace is updated with no increment, so pool members can never claim those tokens. The STRK is physically held in the pool contract with no recovery path.

---

### Finding Description

The `Pool` contract's `compute_rewards_per_unit` function guards against arithmetic overflow by returning `Zero::zero()` whenever `total_stake < min_delegation_for_rewards`:

```cairo
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

The code comment directly above this function acknowledges the consequence:

> **Note**: Delegation rewards lost when pool balance is less than `min_delegation_for_rewards`. The staking contract continues to forward `pool_rewards` to the pool contract even in this case. [1](#0-0) 

The staking contract's `send_rewards_to_delegation_pool` unconditionally transfers STRK tokens to the pool contract address:

```cairo
fn send_rewards_to_delegation_pool(
    ref self: ContractState,
    staker_address: ContractAddress,
    pool_address: ContractAddress,
    amount: Amount,
    token_dispatcher: IERC20Dispatcher,
) {
    token_dispatcher.checked_transfer(recipient: pool_address, amount: amount.into());
    ...
}
``` [2](#0-1) 

The pool contract's `update_rewards_from_staking_contract` then inserts `last + 0` into the cumulative rewards trace:

```cairo
fn update_rewards_from_staking_contract(
    ref self: ContractState, rewards: Amount, pool_balance: Amount,
) {
    self.assert_caller_is_staking_contract();
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
``` [3](#0-2) 

Because the cumulative trace is not advanced, `calculate_rewards` will compute zero for every pool member regardless of how long they wait. The STRK tokens are in the pool contract's ERC-20 balance but are permanently inaccessible — there is no sweep, recovery, or redistribution function.

The `min_delegation_for_rewards` thresholds are:
- STRK pool: `10^18` (1 STRK)
- BTC pool (8 decimals): `10^3` (1000 satoshis / 0.00001 BTC) [4](#0-3) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

STRK reward tokens are transferred from the reward supplier into the pool contract but can never be claimed by any pool member. The loss scales with the pool's proportional share of the staker's total stake multiplied by the number of epochs the pool balance remains below the threshold. There is no administrative escape hatch.

---

### Likelihood Explanation

The entry path requires no privilege:

1. Any address can call `enter_delegation_pool` with any non-zero amount — there is no minimum delegation enforcement at the pool entry point.
2. A new pool, or a pool whose members have all partially exited, can easily have a total balance below 1 STRK.
3. The staking contract's reward forwarding is unconditional; it does not inspect `min_delegation_for_rewards` before calling `send_rewards_to_delegation_pool`.

The flow test `delegate_min_strk_for_rewards_flow_test` explicitly exercises this path and asserts `rewards == Zero::zero()`, confirming the behavior is reachable in production. [5](#0-4) 

---

### Recommendation

The fix should be applied in the staking contract, not the pool contract, to prevent tokens from being sent when they cannot be distributed. Before calling `send_rewards_to_delegation_pool`, the staking contract should check whether the pool balance meets the pool's `min_delegation_for_rewards`. If it does not, the pool's share of rewards should either be retained by the staking contract or returned to the reward supplier rather than forwarded to the pool.

Alternatively, the pool contract's `update_rewards_from_staking_contract` could accumulate the "lost" reward tokens in a separate storage slot and redistribute them once the pool balance crosses the threshold.

---

### Proof of Concept

1. Pool member calls `enter_delegation_pool` with `amount = min_delegation_for_rewards - 1` (e.g., `10^18 - 1` for STRK).
2. Staker attests; the staking contract calls `_update_rewards`.
3. `calculate_staker_pools_rewards` computes a non-zero pool reward proportional to the pool's share of the staker's total stake.
4. `send_rewards_to_delegation_pool` transfers those STRK tokens to the pool contract address.
5. `update_rewards_from_staking_contract(rewards, pool_balance)` is called on the pool; `pool_balance < min_delegation_for_rewards`, so `compute_rewards_per_unit` returns `0`.
6. The cumulative trace entry is `last + 0 = last` — unchanged.
7. Pool member calls `claim_rewards`; `calculate_rewards` returns `0`.
8. The STRK tokens transferred in step 4 remain in the pool contract's ERC-20 balance indefinitely with no mechanism to recover them.

### Citations

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

**File:** src/staking/staking.cairo (L1635-1649)
```text
        fn send_rewards_to_delegation_pool(
            ref self: ContractState,
            staker_address: ContractAddress,
            pool_address: ContractAddress,
            amount: Amount,
            token_dispatcher: IERC20Dispatcher,
        ) {
            token_dispatcher.checked_transfer(recipient: pool_address, amount: amount.into());
            self
                .emit(
                    Events::RewardsSuppliedToDelegationPool {
                        staker_address, pool_address, amount,
                    },
                );
        }
```

**File:** src/flow_test/test.cairo (L1712-1747)
```text
#[test]
fn delegate_min_strk_for_rewards_flow_test() {
    let cfg: StakingInitConfig = Default::default();
    let mut system = SystemConfigTrait::basic_stake_flow_cfg(:cfg).deploy();
    let stake_amount = system.staking.get_min_stake();
    let staker = system.new_staker(amount: stake_amount);
    system.stake(:staker, amount: stake_amount, pool_enabled: true, commission: Zero::zero());
    let pool = system.staking.get_pool(:staker);

    // Setup delegator.
    let delegate_amount = Pool::STRK_CONFIG.min_for_rewards;
    let delegator = system.new_delegator(amount: delegate_amount);

    // Enter pool with less than min STRK for rewards.
    system.delegate(:delegator, :pool, amount: delegate_amount - 1);

    // Attest.
    system.advance_k_epochs_and_attest(:staker);
    system.advance_epoch();

    // Check rewards.
    system.advance_epoch();
    let rewards = system.delegator_claim_rewards(:delegator, :pool);
    assert!(rewards == Zero::zero());

    // Add to delegation.
    system.add_to_delegation_pool(:delegator, :pool, amount: 1);

    // Attest.
    system.advance_k_epochs_and_attest(:staker);

    // Check rewards.
    system.advance_epoch();
    let rewards = system.delegator_claim_rewards(:delegator, :pool);
    assert!(rewards > Zero::zero());
}
```
