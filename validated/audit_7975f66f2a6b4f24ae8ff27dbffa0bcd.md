### Title
Staking Contract Sends Pool Rewards to Pool Contract Even When Pool Balance Is Below Minimum, Permanently Freezing STRK Tokens - (File: src/pool/pool.cairo, src/staking/staking.cairo)

### Summary
When a pool's total delegated balance is below `min_delegation_for_rewards`, the pool contract's `compute_rewards_per_unit` silently returns zero and does not update the cumulative rewards trace. However, the staking contract unconditionally transfers the calculated STRK reward tokens to the pool contract before calling `update_rewards_from_staking_contract`. Because the cumulative trace is never updated, those STRK tokens are permanently frozen in the pool contract with no recovery path.

### Finding Description
The staking contract's `calculate_staker_pools_rewards` calculates `pool_rewards` based on the pool's proportional share of total stake. It only skips a pool if `pool_rewards.is_non_zero()` is false — it does **not** check whether the pool balance meets the pool contract's internal minimum threshold. [1](#0-0) 

When `pool_rewards > 0`, the staking contract proceeds to:
1. Transfer `pool_rewards` STRK tokens to the pool contract via `send_rewards_to_delegation_pool`.
2. Call `pool_dispatcher.update_rewards_from_staking_contract(rewards: pool_rewards, pool_balance: pool_balance.to_native_amount(:decimals))`. [2](#0-1) 

Inside the pool contract, `update_rewards_from_staking_contract` calls `compute_rewards_per_unit`: [3](#0-2) 

`compute_rewards_per_unit` returns **zero** when `total_stake < min_delegation_for_rewards` (1 STRK = 10^18 fris for STRK pools): [4](#0-3) 

Because the return value is zero, the cumulative rewards trace is updated with `last + 0`, meaning no sigma increase is recorded. The STRK tokens already transferred to the pool contract are now unaccounted for in the trace and can never be claimed by any delegator via `claim_rewards`, which distributes only amounts derived from the cumulative trace. [5](#0-4) 

The pool contract has no admin sweep, no recovery function, and no mechanism to return untracked tokens to the staking contract or reward supplier. The code itself acknowledges this in a comment:

> **Note**: Delegation rewards lost when pool balance is less than `min_delegation_for_rewards`. The staking contract continues to forward `pool_rewards` to the pool contract even in this case. [6](#0-5) 

### Impact Explanation
Any STRK tokens forwarded to a pool contract whose total balance is below `min_delegation_for_rewards` are permanently frozen. There is no function in the pool contract to recover them. This constitutes **permanent freezing of unclaimed yield** — a High-severity impact under the allowed scope.

The frozen amount per epoch equals the pool's proportional share of total epoch rewards. Over many epochs with a persistently small pool, the cumulative frozen amount grows unboundedly.

### Likelihood Explanation
The pool contract enforces no minimum delegation amount on entry. The existing flow test `delegate_min_strk_for_rewards_flow_test` explicitly demonstrates that a delegator can enter with `min_for_rewards - 1` (just below 1 STRK): [7](#0-6) 

Any unprivileged delegator can trigger this condition by delegating an amount that keeps the pool's total balance below 1 STRK (e.g., the only delegator in a pool delegates 0.5 STRK). The staker then attests, rewards are calculated, STRK is sent to the pool, and the tokens freeze. No privileged access is required.

### Recommendation
In `calculate_staker_pools_rewards` (or `update_pool_rewards`), add a guard that skips sending rewards to a pool whose native balance is below the pool's `min_delegation_for_rewards`. The pool contract should expose a getter for `min_delegation_for_rewards` so the staking contract can query it before transferring tokens. Alternatively, `update_rewards_from_staking_contract` should return any unused reward amount so the staking contract can redirect it (e.g., back to the reward supplier).

### Proof of Concept
1. Staker stakes and enables a STRK pool with commission = 0.
2. Delegator enters the pool with `amount = 10^18 - 1` (just below `min_delegation_for_rewards`).
3. Advance K epochs and attest. The staking contract calculates `pool_rewards > 0` (proportional to pool's share of total stake) and calls `send_rewards_to_delegation_pool`, transferring STRK to the pool contract.
4. The pool contract's `compute_rewards_per_unit` returns 0 because `pool_balance = 10^18 - 1 < 10^18 = min_delegation_for_rewards`. The cumulative trace is not updated.
5. Delegator calls `claim_rewards` — receives 0 STRK.
6. The STRK tokens transferred in step 3 remain in the pool contract's ERC-20 balance permanently, with no function able to retrieve them.

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

**File:** src/pool/pool.cairo (L879-887)
```text
            // Compute the remaining rewards from (inclusive) the last visited balance change in
            // `pool_member_trace` (or from `from_checkpoint`) to (exclusive) `until_checkpoint`.
            let to_sigma = self.find_sigma(until_checkpoint, curr_epoch: until_epoch);
            rewards +=
                compute_rewards_rounded_down(
                    amount: from_balance, interest: to_sigma - from_sigma, :base_value,
                );

            (rewards, entry_to_claim_from)
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
