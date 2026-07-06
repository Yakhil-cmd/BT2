### Title
Rewards Permanently Frozen in Pool Contract When Pool Balance Is Below `min_delegation_for_rewards` — (`src/pool/pool.cairo`)

---

### Summary

When a pool's total delegated balance is below `min_delegation_for_rewards`, `compute_rewards_per_unit` returns zero, but the staking contract **still transfers the calculated reward tokens** to the pool contract. Because the cumulative rewards trace is not updated, pool members can never claim those tokens. The STRK is permanently frozen inside the pool contract with no recovery path.

---

### Finding Description

**Root cause — `src/pool/pool.cairo`, `compute_rewards_per_unit` (lines 967–978):**

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

When `total_stake < min_delegation_for_rewards`, the function returns `0`. For STRK pools, `min_for_rewards = 10^18` (1 STRK). [1](#0-0) 

**The mismatch — `src/staking/staking.cairo`, `update_pool_rewards` (lines 1865–1891):**

The staking contract first **transfers** the reward tokens to the pool contract, then calls `update_rewards_from_staking_contract`:

```cairo
self.send_rewards_to_delegation_pool(
    :staker_address,
    pool_address: pool_contract,
    amount: pool_rewards,
    token_dispatcher: strk_token_dispatcher,
);
...
pool_dispatcher
    .update_rewards_from_staking_contract(
        rewards: pool_rewards,
        pool_balance: pool_balance.to_native_amount(:decimals),
    );
``` [2](#0-1) 

Inside `update_rewards_from_staking_contract`, the cumulative trace is updated by adding `compute_rewards_per_unit(...)`. When that returns `0`, the trace value is unchanged (`last + 0 = last`): [3](#0-2) 

Pool members' `claim_rewards` computes payouts entirely from the cumulative trace delta. Because the trace never advanced, the transferred STRK is unclaimable. There is no sweep, rescue, or governance function in the pool contract to recover stuck tokens. [4](#0-3) 

The developer comment acknowledges the symptom but not the token-freeze consequence:

> "**Note**: Delegation rewards lost when pool balance is less than `min_delegation_for_rewards`. The staking contract continues to forward `pool_rewards` to the pool contract even in this case." [5](#0-4) 

---

### Impact Explanation

STRK reward tokens are transferred into the pool contract but the accounting record (`cumulative_rewards_trace`) is never incremented. Pool members calling `claim_rewards` receive zero for those epochs. The tokens cannot be recovered by any existing function. This constitutes **permanent freezing of unclaimed yield** (High impact).

---

### Likelihood Explanation

- There is **no minimum delegation amount** for pool members — only a non-zero check (`assert!(amount.is_non_zero(), ...)`). [6](#0-5) 
- For STRK, `min_for_rewards = 10^18` (1 STRK). Any pool whose total delegated balance is below 1 STRK triggers the freeze. [7](#0-6) 
- A new pool with a single delegator contributing less than 1 STRK is a realistic scenario, especially early in a pool's life or for BTC pools with low decimal tokens where the threshold is `10^(decimals-5)`. [8](#0-7) 
- The condition is reachable by any unprivileged pool member without any special access.

---

### Recommendation

Align the transfer with the accounting check. Before calling `send_rewards_to_delegation_pool`, verify that `pool_balance.to_native_amount(:decimals) >= min_delegation_for_rewards` on the pool contract. If the balance is below the threshold, skip both the transfer and the `update_rewards_from_staking_contract` call for that pool. Alternatively, accumulate the undistributed rewards and carry them forward to the next epoch when the balance crosses the threshold.

---

### Proof of Concept

1. Staker stakes ≥ `min_stake` STRK and calls `set_open_for_delegation` to open a STRK pool.
2. A single pool member calls `enter_delegation_pool` with `amount = 0.5 STRK` (500000000000000000 wei). Pool total balance = 0.5 STRK < `min_for_rewards` = 1 STRK.
3. An attestation or `update_rewards` call triggers `_update_rewards`. `calculate_staker_pools_rewards` computes `pool_rewards_including_commission = total_rewards * 0.5 / total_stake > 0` (assuming sufficient epoch rewards), so `pool_rewards > 0` and the pool is included in `pools_rewards_data`.
4. `update_pool_rewards` calls `send_rewards_to_delegation_pool` — `pool_rewards` STRK are transferred to the pool contract.
5. `update_rewards_from_staking_contract` is called with `pool_balance = 0.5 STRK`. `compute_rewards_per_unit` returns `0` (0.5 STRK < 1 STRK). Cumulative trace: `last + 0 = last`.
6. Pool member calls `claim_rewards`. `calculate_rewards` computes `to_sigma - from_sigma = 0`. Payout = 0.
7. The `pool_rewards` STRK tokens remain in the pool contract with no mechanism to recover them — permanently frozen.

### Citations

**File:** src/pool/pool.cairo (L62-64)
```text
    pub(crate) const STRK_CONFIG: TokenRewardsConfig = TokenRewardsConfig {
        decimals: 18, min_for_rewards: 10_u128.pow(18), base_value: 10_u128.pow(28),
    };
```

**File:** src/pool/pool.cairo (L191-191)
```text
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
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

**File:** src/staking/staking.cairo (L1875-1887)
```text
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

**File:** src/pool/utils.cairo (L133-138)
```text
        TokenRewardsConfig {
            decimals,
            min_for_rewards: 10_u128.pow(decimals.into() - 5),
            base_value: 10_u128.pow(decimals.into() + 5),
        }
    }
```
