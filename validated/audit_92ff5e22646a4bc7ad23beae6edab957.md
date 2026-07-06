### Title
Delegation Rewards Permanently Frozen When Pool Balance Falls Below `min_delegation_for_rewards` - (File: src/pool/pool.cairo)

### Summary

When a pool's total delegated balance is below `min_delegation_for_rewards`, the staking contract still transfers STRK reward tokens to the pool contract, but the pool contract records zero per-unit rewards in its `cumulative_rewards_trace`. The transferred STRK tokens are permanently unclaimable by any pool member, constituting a permanent freeze of unclaimed yield.

### Finding Description

The reward distribution flow in `_update_rewards` (staking.cairo) calls `update_pool_rewards`, which unconditionally transfers STRK tokens to the pool contract via `send_rewards_to_delegation_pool`, then calls `pool_dispatcher.update_rewards_from_staking_contract(rewards: pool_rewards, pool_balance: ...)`. [1](#0-0) 

Inside `update_rewards_from_staking_contract`, the pool calls `compute_rewards_per_unit`: [2](#0-1) 

`compute_rewards_per_unit` returns **zero** when `total_stake < min_delegation_for_rewards`, explicitly documented as causing reward loss: [3](#0-2) 

For STRK pools, `min_delegation_for_rewards = 10^18` (1 STRK). For BTC pools with 8 decimals, it is `10^3` (1000 satoshis). [4](#0-3) 

The result is that `cumulative_rewards_trace` receives a zero increment for that epoch: [5](#0-4) 

The STRK tokens are now held by the pool contract but the per-unit reward accounting records zero. Since `claim_rewards` computes payouts exclusively from the `cumulative_rewards_trace`, those tokens can never be claimed. There is no recovery function in the pool contract.

The analog to the external report is direct: in the Ethos vault, `value` is rebased to the available balance and the loss check passes against the rebased value, causing users to lose funds silently. Here, `rewards_per_unit` is rebased to zero when the pool balance is too small, but the actual STRK tokens have already been transferred — the accounting records zero while the contract holds real tokens, permanently freezing them.

### Impact Explanation

STRK reward tokens transferred to a pool contract whose total delegated balance is below `min_delegation_for_rewards` are permanently frozen. No pool member can ever claim them. This matches the allowed impact: **High — Permanent freezing of unclaimed yield**.

### Likelihood Explanation

Any pool whose total delegated balance is below 1 STRK (for STRK pools) or 1000 satoshis (for BTC pools with 8 decimals) triggers this condition. This is reachable by:

1. A delegator entering a pool with a very small amount (no minimum delegation is enforced beyond non-zero).
2. A pool that has had most of its delegators exit, leaving a residual balance below the threshold.
3. A griefing actor who deliberately keeps a pool's balance just below the threshold.

The entry point is `enter_delegation_pool` (callable by any unprivileged delegator) and `exit_delegation_pool_intent`/`exit_delegation_pool_action` (callable by any pool member). [6](#0-5) 

### Recommendation

Decouple the token transfer from the per-unit accounting. Two options:

1. **Skip the transfer when rewards would be zero**: In `calculate_staker_pools_rewards`, before appending to `pool_rewards_array`, check whether `pool_balance.to_native_amount(:decimals) >= min_delegation_for_rewards` in addition to `pool_rewards.is_non_zero()`. If the pool balance is below the threshold, do not transfer and do not call `update_rewards_from_staking_contract`.

2. **Accumulate and defer**: Hold the rewards in the staking contract until the pool balance exceeds the threshold, then transfer the accumulated amount.

Either approach ensures that STRK tokens are never sent to a pool contract that cannot distribute them.

### Proof of Concept

1. Staker S creates a STRK delegation pool.
2. Delegator D enters the pool with `amount = 0.5 STRK` (5 × 10^17 fractions). No minimum is enforced.
3. After K epochs, the attestation contract calls `update_rewards_from_attestation_contract` for S.
4. `calculate_staker_pools_rewards` computes `pool_rewards > 0` (proportional to D's 0.5 STRK share).
5. `update_pool_rewards` transfers `pool_rewards` STRK to the pool contract.
6. `update_rewards_from_staking_contract(rewards: pool_rewards, pool_balance: 5e17)` is called.
7. `compute_rewards_per_unit` checks `5e17 < 1e18 = min_delegation_for_rewards` → returns 0.
8. `cumulative_rewards_trace` records `last + 0 = last` (no change).
9. D calls `claim_rewards` → `calculate_rewards` computes `amount * 0 / base_value = 0`.
10. D receives 0 STRK. The `pool_rewards` STRK tokens remain in the pool contract forever. [7](#0-6) [8](#0-7)

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

**File:** src/pool/pool.cairo (L62-64)
```text
    pub(crate) const STRK_CONFIG: TokenRewardsConfig = TokenRewardsConfig {
        decimals: 18, min_for_rewards: 10_u128.pow(18), base_value: 10_u128.pow(28),
    };
```

**File:** src/pool/pool.cairo (L182-219)
```text
        fn enter_delegation_pool(
            ref self: ContractState, reward_address: ContractAddress, amount: Amount,
        ) {
            // Asserts.
            self.assert_staker_is_active();
            let pool_member = get_caller_address();
            assert!(
                self.pool_member_info.read(pool_member).is_none(), "{}", Error::POOL_MEMBER_EXISTS,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let token_dispatcher = self.token_dispatcher.read();
            let token_address = token_dispatcher.contract_address;
            assert!(token_address != pool_member, "{}", Error::POOL_MEMBER_IS_TOKEN);
            assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
            // Transfer funds from the delegator to the staking contract.
            let staker_address = self.staker_address.read();
            transfer_from_delegator(:pool_member, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);

            self.set_member_balance(:pool_member, :amount);

            // Create the pool member record.
            self
                .pool_member_info
                .write(pool_member, VInternalPoolMemberInfoTrait::new_latest(:reward_address));

            // Emit events.
            self
                .emit(
                    Events::NewPoolMember { pool_member, staker_address, reward_address, amount },
                );
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake: Zero::zero(), new_delegated_stake: amount,
                    },
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
