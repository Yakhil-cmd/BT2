### Title
Pool Rewards Permanently Frozen When Pool Balance Falls Below `min_delegation_for_rewards` - (File: src/pool/pool.cairo)

### Summary

When the total delegated balance in a pool falls below `min_delegation_for_rewards`, the pool's `compute_rewards_per_unit` silently returns zero. The staking contract still transfers the calculated pool reward tokens to the pool contract, but the pool contract records zero in its cumulative rewards trace. Those tokens can never be claimed by any delegator and are permanently frozen in the pool contract.

### Finding Description

In `src/pool/pool.cairo`, the internal `compute_rewards_per_unit` function guards against integer overflow by returning zero when `total_stake < min_delegation_for_rewards`:

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
``` [1](#0-0) 

This function is called from `update_rewards_from_staking_contract`, which is invoked by the staking contract after it has already transferred the reward tokens to the pool:

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
``` [2](#0-1) 

The code's own comment acknowledges the problem:

> **Note**: Delegation rewards lost when pool balance is less than `min_delegation_for_rewards`. The staking contract continues to forward `pool_rewards` to the pool contract even in this case. [3](#0-2) 

The staking contract's `_update_rewards` function claims `total_pools_rewards` tokens from the reward supplier and then calls `update_pool_rewards`, which transfers those tokens to the pool contract and calls `update_rewards_from_staking_contract`. Because the cumulative trace is updated with zero, no delegator can ever claim those tokens — they are permanently locked in the pool contract. [4](#0-3) 

The minimum thresholds are:
- STRK pool: `min_for_rewards = 10^18` (1 STRK)
- BTC pool (8 decimals): `min_for_rewards = 10^(8-5) = 1000 satoshis` [5](#0-4) 

### Impact Explanation

When `pool_balance < min_delegation_for_rewards`, the staking contract mints and transfers reward tokens to the pool contract, but the pool contract records a zero increment in its cumulative rewards trace. Since all delegator reward claims are computed from this trace, those tokens can never be retrieved by any party. This constitutes **permanent freezing of unclaimed yield** — a High-severity impact under the allowed scope.

### Likelihood Explanation

A delegator can enter a pool with any amount, including amounts below `min_delegation_for_rewards`. There is no minimum delegation check in `enter_delegation_pool` or `add_to_delegation_pool`. This is a realistic scenario: a delegator who delegates `min_for_rewards - 1` tokens (e.g., `10^18 - 1` fri for STRK) causes every subsequent epoch's pool rewards to be permanently frozen for as long as the pool balance remains below the threshold. The staker's own rewards are unaffected, so the staker has no incentive to prevent this.

### Recommendation

Before transferring pool reward tokens to the pool contract, the staking contract should check whether the pool balance is at or above `min_delegation_for_rewards`. If it is not, the rewards should not be transferred (or should be redirected), so that tokens are never sent to a pool that will record zero in its cumulative trace. Alternatively, the pool contract's `update_rewards_from_staking_contract` should revert when `pool_balance < min_delegation_for_rewards`, forcing the staking contract to handle this case explicitly rather than silently discarding the tokens.

### Proof of Concept

1. Staker stakes and enables a STRK pool.
2. Delegator calls `enter_delegation_pool` with `amount = STRK_CONFIG.min_for_rewards - 1` (i.e., `10^18 - 1` fri).
3. Staker attests; the staking contract calculates a non-zero `pool_rewards` proportional to the delegated balance.
4. The staking contract claims `pool_rewards` tokens from the reward supplier and transfers them to the pool contract.
5. The pool contract calls `compute_rewards_per_unit(staking_rewards: pool_rewards, total_stake: pool_balance)`. Since `pool_balance < min_delegation_for_rewards`, it returns `0`.
6. The cumulative rewards trace is updated with `last + 0 = last` — no change.
7. The delegator calls `claim_rewards`; the reward calculation yields `amount * 0 / base_value = 0`.
8. The `pool_rewards` tokens remain in the pool contract with no mechanism to recover them.

This is confirmed by the existing flow test `delegate_min_strk_for_rewards_flow_test`, which explicitly verifies that a delegator with `amount = min_for_rewards - 1` receives zero rewards, while the pool contract has already received the forwarded tokens. [6](#0-5)

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

**File:** src/flow_test/test.cairo (L1713-1746)
```text
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
```
