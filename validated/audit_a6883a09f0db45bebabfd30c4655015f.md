### Title
Pool Rewards Permanently Frozen When Total Delegated Balance Is Below `min_delegation_for_rewards` - (File: src/pool/pool.cairo)

### Summary

When a delegation pool's total balance is non-zero but below `min_delegation_for_rewards`, the staking contract still calculates and transfers STRK reward tokens to the pool contract, but the pool contract's `compute_rewards_per_unit` silently returns zero, leaving those tokens permanently unclaimable by any pool member.

### Finding Description

The vulnerability exists across two contracts and two functions:

**Step 1 — Staking contract forwards rewards regardless of minimum threshold**

In `calculate_staker_pools_rewards` (`src/staking/staking.cairo`, lines 1969–1999), the staking contract computes pool rewards using the raw `pool_balance_curr_epoch`. There is no check against `min_delegation_for_rewards` at this stage. If `pool_balance_curr_epoch` is non-zero (even if it is 0.5 STRK, below the 1 STRK minimum), the rewards are computed and appended to `pool_rewards_array`: [1](#0-0) 

Then in `update_pool_rewards` (`src/staking/staking.cairo`, lines 1865–1891), the staking contract physically transfers the STRK tokens to the pool contract and calls `update_rewards_from_staking_contract`: [2](#0-1) 

**Step 2 — Pool contract silently discards the rewards in the cumulative trace**

In `update_rewards_from_staking_contract` (`src/pool/pool.cairo`, lines 569–587), the pool contract calls `compute_rewards_per_unit` to update the cumulative rewards trace: [3](#0-2) 

In `compute_rewards_per_unit` (`src/pool/pool.cairo`, lines 967–978), when `total_stake < min_delegation_for_rewards`, the function returns zero. The cumulative trace is updated with `last + 0`, meaning no reward-per-unit is ever recorded for that epoch: [4](#0-3) 

The code comment at line 964 explicitly acknowledges this: *"Delegation rewards lost when pool balance is less than `min_delegation_for_rewards`. The staking contract continues to forward `pool_rewards` to the pool contract even in this case."*

For STRK pools, `min_delegation_for_rewards = 10^18` (1 STRK): [5](#0-4) 

**Result**: The STRK tokens are physically held in the pool contract's token balance but the cumulative rewards trace is never updated for those epochs. Since `claim_rewards` computes payouts exclusively from the cumulative trace, those tokens can never be claimed by any pool member and there is no recovery function.

### Impact Explanation

This is **permanent freezing of unclaimed yield** (High severity per the allowed impact scope). Any STRK rewards forwarded to a pool contract during epochs where the total delegated balance is non-zero but below `min_delegation_for_rewards` (1 STRK) are irreversibly locked in the pool contract. There is no administrative function, sweep mechanism, or fallback path to recover them.

### Likelihood Explanation

This is realistically reachable. A delegator can enter a pool with any amount above zero (the protocol enforces no minimum delegation amount at the pool entry point). If the total pool balance is between 1 FRI and `10^18 - 1` FRI (i.e., less than 1 STRK), every attestation epoch during that period will silently burn the proportional pool rewards. This is especially likely during the early life of a pool before it accumulates sufficient delegation.

The flow test `delegate_min_strk_for_rewards_flow_test` confirms this path is reachable and that rewards are zero when balance is below the threshold, but does not verify that the forwarded tokens are recoverable: [6](#0-5) 

### Recommendation

The staking contract should skip forwarding rewards to a pool when the pool's delegated balance is below `min_delegation_for_rewards`. Specifically, in `calculate_staker_pools_rewards`, add a guard analogous to the one already present in `compute_rewards_per_unit`: if `pool_balance_curr_epoch.to_native_amount(decimals) < pool_min_delegation_for_rewards`, do not append the pool to `pool_rewards_array`. This ensures no tokens are transferred to the pool contract for epochs where they cannot be distributed.

### Proof of Concept

1. Staker stakes and opens a STRK delegation pool.
2. Delegator enters the pool with `0.5 STRK` (5 × 10^17 FRI) — below `min_delegation_for_rewards = 10^18`.
3. Staker attests; `update_rewards` is called.
4. `calculate_staker_pools_rewards` computes non-zero `pool_rewards` proportional to 0.5 STRK and appends the pool to `pool_rewards_array`.
5. `update_pool_rewards` transfers those STRK tokens to the pool contract and calls `update_rewards_from_staking_contract(rewards=R, pool_balance=5e17)`.
6. Inside `update_rewards_from_staking_contract`, `compute_rewards_per_unit` returns `0` because `5e17 < 10^18`.
7. The cumulative trace is updated with `last + 0` — no change.
8. The delegator calls `claim_rewards`; the calculation over the cumulative trace yields zero.
9. The STRK tokens `R` remain in the pool contract's balance permanently, with no mechanism to recover them.

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

**File:** src/flow_test/test.cairo (L1711-1747)
```text
/// Attest and check rewards
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
