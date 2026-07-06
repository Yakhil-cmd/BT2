### Title
Pool Rewards Transferred But Permanently Unclaimable When Pool Balance Is Below `min_for_rewards` - (File: src/staking/staking.cairo, src/pool/pool.cairo)

### Summary
The staking contract calculates pool rewards using normalized 18-decimal amounts, but the pool contract's `compute_rewards_per_unit` enforces a `min_for_rewards` threshold on the **native** token amount. When the total pool balance is below `min_for_rewards` in native units but non-zero in normalized units, `pool_rewards` is computed as non-zero, STRK tokens are physically transferred to the pool contract, yet the cumulative rewards trace is never updated — permanently locking those STRK tokens inside the pool with no mechanism for pool members to claim them.

### Finding Description

**Step 1 — Reward calculation uses normalized amounts.**

In `calculate_staker_pools_rewards`, the per-pool reward is computed using `pool_balance_curr_epoch.to_amount_18_decimals()`: [1](#0-0) 

If `pool_rewards > 0`, the pool is appended to `pool_rewards_array`: [2](#0-1) 

**Step 2 — STRK tokens are unconditionally transferred to the pool.**

In `update_pool_rewards`, for every entry in `pools_rewards_data`, STRK tokens are sent to the pool contract and then `update_rewards_from_staking_contract` is called with the **native** amount: [3](#0-2) 

**Step 3 — Pool's `compute_rewards_per_unit` silently returns zero for sub-threshold balances.**

Inside `update_rewards_from_staking_contract`, the pool updates its cumulative rewards trace by calling `self.compute_rewards_per_unit(staking_rewards: rewards, total_stake: pool_balance)`. When `pool_balance < min_for_rewards` (native units), this returns zero: [4](#0-3) 

The test utility mirrors this exact check: [5](#0-4) 

For STRK: `min_for_rewards = 10^18` (1 STRK). For BTC-8: `min_for_rewards = 10^3 = 1000 satoshis`. [6](#0-5) 

**Step 4 — Cumulative trace not updated → rewards unclaimable.**

Because `compute_rewards_per_unit` returns zero, the cumulative rewards trace is updated with `last + 0`. Pool members' `calculate_rewards` reads this trace to compute claimable amounts — it will return zero for the affected epoch. The STRK tokens already transferred to the pool contract have no corresponding trace entry and are permanently inaccessible. [7](#0-6) 

### Impact Explanation

STRK reward tokens are physically transferred into the pool contract but are permanently frozen there. No pool member can ever claim them because the cumulative rewards trace was not incremented. There is no recovery function in the pool contract. This constitutes **permanent freezing of unclaimed yield**, matching the allowed High impact.

### Likelihood Explanation

Any unprivileged delegator can trigger this by delegating an amount below `min_for_rewards` in native units. The existing test `delegate_min_strk_for_rewards_flow_test` and `PoolWithMinBtcFlow` confirm that such delegations are accepted without restriction: [8](#0-7) [9](#0-8) 

For BTC pools the threshold is only 1000 satoshis (~$0.001 at current prices), making this trivially reachable. Likelihood: **Medium**.

### Recommendation

Before transferring STRK tokens to the pool, check whether `pool_balance.to_native_amount(:decimals) >= min_for_rewards`. If the pool balance is below the threshold, do not transfer the rewards to the pool (and do not call `update_rewards_from_staking_contract`). Alternatively, credit those rewards to the staker or to a protocol treasury rather than sending them to a pool that cannot distribute them.

### Proof of Concept

1. Staker stakes and opens a BTC delegation pool (8-decimal token, `min_for_rewards = 1000` satoshis).
2. Delegator calls `enter_delegation_pool` with `amount = 999` satoshis. No minimum-amount check prevents this.
3. After K epochs, attestation triggers `update_rewards_from_attestation_contract` → `_update_rewards` → `calculate_staker_pools_rewards`.
4. `pool_balance_curr_epoch.to_amount_18_decimals() = 999 × 10^10 > 0`; with `btc_total_stake = pool_balance_curr_epoch` (only pool), `pool_rewards_including_commission = btc_total_rewards` (non-zero). After commission split, `pool_rewards > 0`.
5. `pool_rewards > 0` → pool appended to `pool_rewards_array` → `send_rewards_to_delegation_pool` transfers STRK to pool contract.
6. `update_rewards_from_staking_contract(rewards: pool_rewards, pool_balance: 999)` is called. `999 < 1000 = min_for_rewards` → `compute_rewards_per_unit` returns 0 → cumulative trace unchanged.
7. Delegator calls `claim_rewards` → `calculate_rewards` reads unchanged trace → returns 0.
8. STRK tokens are permanently locked in the pool contract with no recovery path. [10](#0-9) [11](#0-10) [4](#0-3)

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

**File:** src/staking/staking.cairo (L1979-1985)
```text
                let pool_rewards_including_commission = if total_stake.is_non_zero() {
                    mul_wide_and_div(
                        lhs: total_rewards,
                        rhs: pool_balance_curr_epoch.to_amount_18_decimals(),
                        div: total_stake.to_amount_18_decimals(),
                    )
                        .expect_with_err(err: InternalError::REWARDS_COMPUTATION_OVERFLOW)
```

**File:** src/staking/staking.cairo (L1994-1998)
```text
                if pool_rewards.is_non_zero() {
                    pool_rewards_array
                        .append(
                            (pool_contract, token_address, pool_balance_curr_epoch, pool_rewards),
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

**File:** src/test_utils.cairo (L1350-1358)
```text
pub(crate) fn compute_rewards_per_unit(
    staking_rewards: Amount, total_stake: Amount, token_address: ContractAddress,
) -> Index {
    let (min_amount_for_rewards, base_value) = _get_reward_calculation_params(:token_address);
    if total_stake < min_amount_for_rewards {
        return Zero::zero();
    }
    mul_wide_and_div(lhs: staking_rewards, rhs: base_value, div: total_stake)
        .expect_with_err(err: InternalError::REWARDS_COMPUTATION_OVERFLOW)
```

**File:** src/flow_test/test.cairo (L1722-1735)
```text
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
```

**File:** src/flow_test/flows.cairo (L4215-4225)
```text
        let delegate_amount = TEST_MIN_BTC_FOR_REWARDS;
        let delegator = system.new_btc_delegator(amount: delegate_amount, :token);
        system.delegate_btc(:delegator, :pool, amount: delegate_amount - 1, :token);

        system.advance_k_epochs_and_attest(:staker);
        system.advance_epoch();

        let pool_rewards = system.delegator_claim_rewards(:delegator, :pool);
        let staker_rewards = system.staker_claim_rewards(:staker);
        assert!(pool_rewards.is_zero());
        assert!(staker_rewards.is_non_zero());
```
