### Title
Pool Rewards Permanently Frozen When Pool Balance Falls Below `min_delegation_for_rewards` - (File: src/pool/pool.cairo)

### Summary

When the total delegated balance in a `Pool` contract falls below `min_delegation_for_rewards`, the staking contract continues to forward pool reward tokens to the pool contract, but the pool's sigma-based accounting records zero interest for those epochs. The forwarded tokens accumulate in the pool contract's token balance with no mechanism to recover or redistribute them, permanently freezing unclaimed yield.

### Finding Description

The `Pool` contract distributes rewards to delegators using a cumulative sigma trace. Each epoch, the staking contract calls `update_rewards_from_staking_contract(rewards, pool_balance)` on the pool, which internally calls `compute_rewards_per_unit`:

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
    ...
}
``` [1](#0-0) 

When `total_stake < min_delegation_for_rewards`, this returns `Zero::zero()`, so the cumulative sigma does not increase. The code comment directly above this function acknowledges the consequence:

> **Note**: Delegation rewards lost when pool balance is less than `min_delegation_for_rewards`. The staking contract continues to forward `pool_rewards` to the pool contract even in this case. [2](#0-1) 

For STRK pools, `min_delegation_for_rewards = 10^18` (1 STRK). [3](#0-2) 

The staking contract's `send_rewards_to_delegation_pool` performs an unconditional ERC-20 transfer to the pool contract address:

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
``` [4](#0-3) 

Because sigma never increases for those epochs, `calculate_rewards` in the pool will compute zero rewards for all delegators across those epochs, regardless of how many tokens were physically transferred in. There is no `sweep`, `recover`, or admin-withdrawal function anywhere in the `Pool` contract. [5](#0-4) 

### Impact Explanation

Reward tokens forwarded to the pool contract while `pool_balance < min_delegation_for_rewards` are permanently frozen. No delegator can claim them (sigma-based calculation yields zero), and no privileged function exists to recover them. This matches **High: Permanent freezing of unclaimed yield**.

Quantitatively: if total network stake is 1 M STRK, yearly mint is 100 M STRK, and a pool holds 0.5 STRK for 100 epochs, approximately `(0.5 / 1,000,000) × (100,000,000 / 365) × 100 ≈ 13.7 STRK` accumulates permanently in the pool contract. The amount grows linearly with time.

### Likelihood Explanation

Realistic triggering conditions:
1. A staker opens a pool and a single delegator enters with a sub-threshold amount (< 1 STRK for STRK pools).
2. All but one delegator exit via `exit_delegation_pool_intent` / `exit_delegation_pool_action`, leaving a residual balance below the threshold.
3. A BTC pool with low-decimal token where the threshold is `10^(decimals-5)`.

The staker remains active and attesting, so `update_rewards` is called every block, continuously forwarding pool rewards to the pool contract. No special permissions or adversarial action are required — normal protocol operation is sufficient.

### Recommendation

Two complementary fixes:

1. **Skip the transfer when sigma would be zero**: In the staking contract's `_update_rewards` logic, check whether `pool_balance < min_delegation_for_rewards` before calling `send_rewards_to_delegation_pool`. If so, do not transfer the pool rewards (or redirect them to the staker's own rewards).

2. **Add a sweep function to the Pool contract**: Similar to the `sweep` function recommended in the external report for `BaseRewarder`, add an admin-callable function that transfers any token balance in excess of the sum of all delegators' claimable rewards to a designated recovery address.

### Proof of Concept

1. Staker stakes and opens a STRK pool.
2. Delegator enters with `amount = 0.5 × 10^18` (0.5 STRK, below `min_delegation_for_rewards = 10^18`).
3. Staker attests every epoch for N epochs. Each epoch, `update_rewards` → `_update_rewards` → `send_rewards_to_delegation_pool` transfers `pool_rewards` tokens to the pool contract.
4. Each epoch, `update_rewards_from_staking_contract` is called on the pool; `compute_rewards_per_unit` returns 0 because `pool_balance < min_delegation_for_rewards`.
5. After N epochs, `pool.claim_rewards(delegator)` returns 0.
6. `IERC20(STRK).balance_of(pool_contract)` shows N × `pool_rewards` tokens permanently locked with no callable function to recover them. [6](#0-5) [7](#0-6)

### Citations

**File:** src/pool/pool.cairo (L62-64)
```text
    pub(crate) const STRK_CONFIG: TokenRewardsConfig = TokenRewardsConfig {
        decimals: 18, min_for_rewards: 10_u128.pow(18), base_value: 10_u128.pow(28),
    };
```

**File:** src/pool/pool.cairo (L335-377)
```text
        fn claim_rewards(ref self: ContractState, pool_member: ContractAddress) -> Amount {
            // Asserts.
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let caller_address = get_caller_address();
            let reward_address = pool_member_info.reward_address;
            assert!(
                caller_address == pool_member || caller_address == reward_address,
                "{}",
                Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );

            let until_checkpoint = self.get_current_checkpoint(:pool_member);

            // Calculate rewards and update entry_to_claim_from.
            let (mut rewards, updated_entry_to_claim_from) = self
                .calculate_rewards(
                    :pool_member,
                    from_checkpoint: pool_member_info.reward_checkpoint,
                    :until_checkpoint,
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
            rewards += pool_member_info._unclaimed_rewards_from_v0;
            pool_member_info._unclaimed_rewards_from_v0 = Zero::zero();
            pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
            pool_member_info.reward_checkpoint = until_checkpoint;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());

            // Emit event.
            self
                .emit(
                    Events::PoolMemberRewardClaimed {
                        pool_member, reward_address, amount: rewards,
                    },
                );

            rewards
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
