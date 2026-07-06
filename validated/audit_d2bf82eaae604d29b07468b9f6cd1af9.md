### Title
STRK Rewards Permanently Frozen in Pool Contract When Pool Balance Falls Below `min_delegation_for_rewards` - (File: src/pool/pool.cairo)

### Summary

When a delegation pool's total balance is below `min_delegation_for_rewards`, the staking contract still calculates and physically transfers STRK reward tokens to the pool contract, but the pool's internal accounting (`compute_rewards_per_unit`) returns zero, making those tokens permanently unclaimable by any delegator. There is no admin or governance function in the pool contract to recover these stuck funds.

### Finding Description

The reward distribution pipeline has a two-step process:

**Step 1 – Staking contract calculates and sends pool rewards** (`src/staking/staking.cairo`, `_update_rewards` → `update_pool_rewards`):

`calculate_staker_pools_rewards` computes `pool_rewards` proportional to the pool's normalized balance vs. total staking power. If the pool has any non-zero balance, `pool_rewards` will be non-zero. These tokens are then physically transferred to the pool contract via `send_rewards_to_delegation_pool`. [1](#0-0) 

**Step 2 – Pool contract updates its internal accounting** (`src/pool/pool.cairo`, `update_rewards_from_staking_contract`):

After receiving the STRK tokens, the pool calls `compute_rewards_per_unit`. If `total_stake < min_delegation_for_rewards`, this function returns **zero**, so the `cumulative_rewards_trace` is updated with `last + 0 = last` — no change. [2](#0-1) 

The code itself documents this discrepancy: [3](#0-2) 

Because `cumulative_rewards_trace` is not advanced, the `find_sigma` / `calculate_rewards` logic in `claim_rewards` will compute zero rewards for that epoch for every delegator, regardless of how much STRK was deposited into the pool contract. [4](#0-3) 

There is no `withdrawProfits`, sweep, or governance-rescue function anywhere in the pool contract. The only token-exit paths are `claim_rewards` (gated on the cumulative trace) and `exit_delegation_pool_action` (returns only the staked principal). [5](#0-4) 

### Impact Explanation

STRK reward tokens are physically transferred into the pool contract but are permanently unclaimable by delegators. They accumulate silently across every epoch in which the pool balance remains below the threshold. The only escape is a contract upgrade that adds a recovery path — identical to the M-12 resolution path. This constitutes **permanent freezing of unclaimed yield**.

### Likelihood Explanation

For STRK pools, `min_delegation_for_rewards = 10^18` (1 STRK). Any delegator who enters with less than 1 STRK triggers the condition. For BTC pools, the threshold is `10^(decimals−5)` — for 8-decimal BTC that is 1000 satoshis (0.00001 BTC), a very low bar. The flow test `PoolWithMinBtcFlow` explicitly exercises this path and confirms `pool_rewards == 0` while `staker_rewards > 0`, proving the STRK is deposited but not credited. [6](#0-5) 

The condition is reachable by any unprivileged delegator with no special access required.

### Recommendation

Either:
1. **Guard the transfer**: In `calculate_staker_pools_rewards`, skip sending `pool_rewards` to the pool contract when the pool's native balance is below `min_delegation_for_rewards` (redirect those rewards to the staker as additional commission, or back to the reward supplier).
2. **Add a recovery function**: Add a governance-callable `sweep_dust_rewards` function to the pool contract that transfers any STRK balance in excess of the tracked delegated principal to a designated address.

### Proof of Concept

1. Staker stakes and opens a STRK delegation pool.
2. Delegator enters with `amount = 0.5 STRK` (below `min_delegation_for_rewards = 1 STRK`).
3. Staker attests; `_update_rewards` runs:
   - `calculate_staker_pools_rewards` computes `pool_rewards > 0` (proportional to 0.5 STRK share).
   - `send_rewards_to_delegation_pool` transfers those STRK to the pool contract.
   - `update_rewards_from_staking_contract(rewards=X, pool_balance=0.5e18)` is called.
   - `compute_rewards_per_unit`: `0.5e18 < 1e18` → returns `0`.
   - `cumulative_rewards_trace` unchanged.
4. Delegator calls `claim_rewards` → receives `0`.
5. STRK tokens `X` remain in the pool contract balance permanently with no callable path to recover them. [4](#0-3) [2](#0-1) [7](#0-6)

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
