### Title
Pool Rewards Permanently Frozen When Delegation Balance Falls Below `min_delegation_for_rewards` - (File: src/pool/pool.cairo)

### Summary
When a delegation pool's total balance is below `min_delegation_for_rewards`, the staking contract still calculates and transfers STRK reward tokens to the pool contract, but `compute_rewards_per_unit` returns zero, meaning the `cumulative_rewards_trace` is never incremented. The transferred STRK tokens are permanently locked in the pool contract with no recovery mechanism.

### Finding Description
The root cause is a mismatch between two independent checks:

**Step 1 — Staking contract calculates and sends pool rewards** (`src/staking/staking.cairo`, `calculate_staker_pools_rewards`):

```cairo
let pool_rewards_including_commission = if total_stake.is_non_zero() {
    mul_wide_and_div(
        lhs: total_rewards,
        rhs: pool_balance_curr_epoch.to_amount_18_decimals(),
        div: total_stake.to_amount_18_decimals(),
    )...
} else {
    Zero::zero()
};
...
if pool_rewards.is_non_zero() {
    pool_rewards_array.append((pool_contract, token_address, pool_balance_curr_epoch, pool_rewards));
}
``` [1](#0-0) 

If `pool_balance_curr_epoch` is non-zero but below `min_delegation_for_rewards`, `pool_rewards` is still non-zero (it is proportional to `pool_balance / total_stake`). The rewards are added to the array and STRK tokens are transferred to the pool contract via `send_rewards_to_delegation_pool`.

**Step 2 — Pool contract silently discards the reward** (`src/pool/pool.cairo`, `compute_rewards_per_unit`):

```cairo
fn compute_rewards_per_unit(
    self: @ContractState, staking_rewards: Amount, total_stake: Amount,
) -> Index {
    // Return zero if the total stake is too small, to avoid overflow below.
    if total_stake < self.min_delegation_for_rewards.read() {
        return Zero::zero();
    }
    ...
}
``` [2](#0-1) 

When `total_stake < min_delegation_for_rewards`, the function returns 0. The `cumulative_rewards_trace` is updated with a zero increment:

```cairo
self.cumulative_rewards_trace.insert(
    key: self.get_current_epoch(),
    value: last + self.compute_rewards_per_unit(staking_rewards: rewards, total_stake: pool_balance),
);
``` [3](#0-2) 

Since `calculate_rewards` uses the `cumulative_rewards_trace` to compute delegator rewards, and the trace was not incremented, delegators can never claim the transferred STRK tokens. The code itself acknowledges this:

> **Note**: Delegation rewards lost when pool balance is less than `min_delegation_for_rewards`. The staking contract continues to forward `pool_rewards` to the pool contract even in this case. [4](#0-3) 

There is no function in the pool contract to recover stuck STRK tokens. `claim_rewards` only pays out what the `cumulative_rewards_trace` records, and `exit_delegation_pool_action` only returns the staked principal. [5](#0-4) 

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

Every time a staker attests (or `update_rewards` is called) while the pool's total delegation is non-zero but below `min_delegation_for_rewards`, the proportional STRK reward tokens are transferred into the pool contract and permanently locked. No delegator can ever claim them, and no admin function exists to recover them. The loss accumulates with every reward distribution event.

For STRK pools, `min_delegation_for_rewards = 10^18` (1 STRK). [6](#0-5) 

For BTC pools with 8 decimals, `min_delegation_for_rewards = 10^3 = 1000` native units (0.00001 BTC). [7](#0-6) 

### Likelihood Explanation
**Low-Medium.** The scenario requires a pool whose total delegated balance is non-zero but below the threshold. This can occur naturally:
- A single delegator enters a STRK pool with less than 1 STRK.
- All other delegators exit a pool, leaving only a small residual balance.
- A BTC pool with a very small delegation (below 0.00001 BTC).

No privileged access is required. Any unprivileged delegator can create this condition by entering a pool with a small amount.

### Recommendation
The staking contract should not transfer rewards to the pool contract when `pool_balance < min_delegation_for_rewards`. The guard should be applied in `calculate_staker_pools_rewards` before adding to `pool_rewards_array`, or the pool contract should return the received tokens when `compute_rewards_per_unit` returns zero. Alternatively, a recovery function should be added to the pool contract to allow redistribution of stuck reward tokens.

### Proof of Concept
1. Staker stakes and enables a STRK pool.
2. Delegator enters the pool with `0.5 STRK` (below `min_delegation_for_rewards = 1 STRK`).
3. K epochs pass so the delegation becomes effective.
4. Staker attests (V2) or `update_rewards` is called (V3).
5. `calculate_staker_pools_rewards` computes `pool_rewards > 0` (since `pool_balance = 0.5 STRK` is non-zero relative to `total_stake`).
6. STRK reward tokens are transferred to the pool contract via `send_rewards_to_delegation_pool`.
7. `update_rewards_from_staking_contract(rewards, pool_balance=0.5e18)` is called on the pool.
8. `compute_rewards_per_unit` returns 0 because `0.5e18 < 1e18`.
9. `cumulative_rewards_trace` is updated with zero increment.
10. Delegator calls `claim_rewards` → receives 0 rewards.
11. STRK reward tokens remain permanently locked in the pool contract.

### Citations

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

**File:** src/pool/pool.cairo (L576-587)
```text
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

**File:** src/pool/utils.cairo (L131-137)
```text
        let decimals = token_dispatcher.decimals();
        assert!(decimals >= 5 && decimals <= 18, "{}", GenericError::INVALID_TOKEN_DECIMALS);
        TokenRewardsConfig {
            decimals,
            min_for_rewards: 10_u128.pow(decimals.into() - 5),
            base_value: 10_u128.pow(decimals.into() + 5),
        }
```
