### Title
Pool Rewards Permanently Frozen When Pool Balance Falls Below `min_delegation_for_rewards` - (File: `src/pool/pool.cairo`)

### Summary

The staking contract calculates and transfers STRK rewards to a delegation pool even when the pool's total balance is below `min_delegation_for_rewards`. The pool contract's `compute_rewards_per_unit` silently returns zero in this case, causing the transferred STRK tokens to be permanently frozen inside the pool contract with no recovery path.

### Finding Description

The vulnerability involves a mismatch between where the "too-small balance" guard lives and where the reward transfer happens.

**Root cause — `src/pool/pool.cairo`, `compute_rewards_per_unit`:** [1](#0-0) 

When `total_stake < min_delegation_for_rewards`, the function returns `Zero::zero()`, so `cumulative_rewards_trace` is never updated. The developer comment directly above this function acknowledges the problem: [2](#0-1) 

**The staking contract does not mirror this guard before transferring funds.**

In `src/staking/staking.cairo`, `calculate_staker_pools_rewards` computes a non-zero `pool_rewards` whenever `pool_balance_curr_epoch > 0`, regardless of whether it is above `min_delegation_for_rewards`: [3](#0-2) 

`update_pool_rewards` then unconditionally transfers those rewards to the pool contract and calls `update_rewards_from_staking_contract`: [4](#0-3) 

The pool contract receives the STRK tokens but, because `compute_rewards_per_unit` returns zero, the `cumulative_rewards_trace` is not advanced: [5](#0-4) 

Pool members' `calculate_rewards` computes rewards as the difference between two `cumulative_rewards_trace` entries: [6](#0-5) 

Because the trace was never updated, the difference is zero and `claim_rewards` pays out nothing. The STRK tokens sit in the pool contract forever — there is no sweep or recovery function.

**Threshold values** (`src/pool/pool.cairo`): [7](#0-6) 

- STRK: `min_for_rewards = 10^18` (1 STRK)
- BTC (8 dec): `min_for_rewards = 10^(decimals−5) = 10^3` (1 000 satoshis)

**No minimum delegation is enforced** in `enter_delegation_pool` or `add_to_delegation_pool`: [8](#0-7) 

### Impact Explanation

Any STRK forwarded to a pool whose total balance is below `min_delegation_for_rewards` is permanently frozen inside the pool contract. Pool members can never claim it, and no admin function exists to recover it. This constitutes **permanent freezing of unclaimed yield** (High impact per the allowed scope).

Additionally, the staker still receives commission on these unclaimable pool rewards (commission is split before the transfer), meaning the staker profits while delegators lose their yield.

### Likelihood Explanation

The trigger is reachable by any unprivileged delegator:

1. **Small initial delegation**: delegate any amount below 1 STRK (e.g., 0.5 STRK). No minimum-delegation guard exists.
2. **Partial exit**: a delegator with 2 STRK calls `exit_delegation_pool_intent(amount: 1.5 STRK)`, leaving 0.5 STRK in the pool. Every subsequent `update_rewards` call will silently burn that epoch's pool rewards.

The condition is persistent: once the pool balance drops below the threshold, every block's rewards for that pool are lost until new delegation pushes the balance back above the threshold.

### Recommendation

Add the `min_delegation_for_rewards` guard in the **staking contract** before rewards are transferred, so that no STRK is sent to a pool that cannot distribute it:

```cairo
// In calculate_staker_pools_rewards, before appending to pool_rewards_array:
let native_pool_balance = pool_balance_curr_epoch.to_native_amount(:decimals);
let min_for_rewards = IPoolDispatcher { contract_address: pool_contract }
    .get_min_delegation_for_rewards();
if native_pool_balance < min_for_rewards {
    continue; // skip — do not transfer rewards
}
```

Alternatively, expose `min_delegation_for_rewards` as a constant and replicate the check in `calculate_staker_pools_rewards` so that `pool_rewards` is forced to zero before `update_pool_rewards` is called.

### Proof of Concept

1. Delegator calls `pool.enter_delegation_pool(reward_address, amount: 5 * 10^17)` — delegates 0.5 STRK (below the 1 STRK threshold).
2. Pool's `staker_delegated_balance_trace` records 0.5 STRK.
3. Sequencer calls `staking.update_rewards(staker_address, disable_rewards: false)`.
4. `calculate_staker_pools_rewards` computes `pool_rewards > 0` (e.g., `total_rewards * 0.5 / total_staker_stake`).
5. `update_pool_rewards` transfers `pool_rewards` STRK to the pool contract via `send_rewards_to_delegation_pool`.
6. `pool.update_rewards_from_staking_contract(rewards: pool_rewards, pool_balance: 5*10^17)` is called.
7. `compute_rewards_per_unit`: `5*10^17 < 10^18` → returns `0`. `cumulative_rewards_trace` unchanged.
8. Delegator calls `pool.claim_rewards(pool_member)` → receives `0`.
9. The transferred STRK is permanently locked in the pool contract with no recovery path.

### Citations

**File:** src/pool/pool.cairo (L62-64)
```text
    pub(crate) const STRK_CONFIG: TokenRewardsConfig = TokenRewardsConfig {
        decimals: 18, min_for_rewards: 10_u128.pow(18), base_value: 10_u128.pow(28),
    };
```

**File:** src/pool/pool.cairo (L182-199)
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

**File:** src/pool/pool.cairo (L837-888)
```text
        fn calculate_rewards(
            self: @ContractState,
            pool_member: ContractAddress,
            from_checkpoint: PoolMemberCheckpoint,
            until_checkpoint: PoolMemberCheckpoint,
            mut entry_to_claim_from: VecIndex,
        ) -> (Amount, VecIndex) {
            let pool_member_trace = self.pool_member_epoch_balance.entry(pool_member);
            // Note: `until_epoch` is the current epoch.
            let until_epoch = until_checkpoint.epoch();

            let mut rewards = 0;

            let pool_member_trace_length = pool_member_trace.length();

            let mut from_sigma = self.find_sigma(from_checkpoint, curr_epoch: until_epoch);
            let mut from_balance = from_checkpoint.balance();

            let base_value = self.staking_rewards_base_value.read();

            // **Note**: The loop iterates over the balance changes in the pool member's balance
            // trace. This loop is unbounded but unlikely to exceed gas limits.
            while entry_to_claim_from < pool_member_trace_length {
                let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
                // If the balance change is after `until_epoch` (and therefore does not affect
                // the current reward computation), exit the loop.
                if pool_member_checkpoint.epoch() >= until_epoch {
                    break;
                }

                // Compute rewards from (inclusive) the previous balance change (or from
                // `from_checkpoint`) to (exclusive) the current entry.
                let to_sigma = self.find_sigma(pool_member_checkpoint, curr_epoch: until_epoch);
                rewards +=
                    compute_rewards_rounded_down(
                        amount: from_balance, interest: to_sigma - from_sigma, :base_value,
                    );
                from_sigma = to_sigma;
                from_balance = pool_member_checkpoint.balance();
                entry_to_claim_from += 1;
            }

            // Compute the remaining rewards from (inclusive) the last visited balance change in
            // `pool_member_trace` (or from `from_checkpoint`) to (exclusive) `until_checkpoint`.
            let to_sigma = self.find_sigma(until_checkpoint, curr_epoch: until_epoch);
            rewards +=
                compute_rewards_rounded_down(
                    amount: from_balance, interest: to_sigma - from_sigma, :base_value,
                );

            (rewards, entry_to_claim_from)
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

**File:** src/staking/staking.cairo (L1872-1890)
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
            }
            pool_rewards_list
```

**File:** src/staking/staking.cairo (L1978-1999)
```text
                // Calculate rewards for this pool.
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
