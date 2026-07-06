### Title
Rewards Permanently Frozen in Pool Contract When Total Delegated Stake Falls Below `min_delegation_for_rewards` - (File: src/pool/pool.cairo)

### Summary
The `Pool::compute_rewards_per_unit` function returns zero when the pool's total delegated stake is below `min_delegation_for_rewards`. However, the staking contract unconditionally transfers reward tokens to the pool contract before calling `update_rewards_from_staking_contract`. Because the pool contract does not track these rewards (the cumulative trace is not updated), the transferred tokens are permanently frozen inside the pool contract with no recovery path.

### Finding Description
In `src/pool/pool.cairo`, the internal function `compute_rewards_per_unit` contains an early-return guard:

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

The code comment on the function itself acknowledges the consequence:

> **Note**: Delegation rewards lost when pool balance is less than `min_delegation_for_rewards`. The staking contract continues to forward `pool_rewards` to the pool contract even in this case. [2](#0-1) 

The staking contract's `send_rewards_to_delegation_pool` performs an unconditional ERC-20 transfer to the pool address before the pool's accounting is updated:

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
``` [3](#0-2) 

When `total_stake < min_delegation_for_rewards`, the call chain is:

1. Staking contract transfers `X` STRK to pool contract address (tokens now reside in pool).
2. Staking contract calls `pool.update_rewards_from_staking_contract(rewards=X, pool_balance=Y)`.
3. Pool calls `compute_rewards_per_unit(X, Y)` → returns `0` because `Y < min_delegation_for_rewards`.
4. Cumulative rewards trace is incremented by `0`; no pool member can ever claim the `X` tokens.

The `min_delegation_for_rewards` for STRK is `10^18` (1 STRK):

```cairo
pub(crate) const STRK_CONFIG: TokenRewardsConfig = TokenRewardsConfig {
    decimals: 18, min_for_rewards: 10_u128.pow(18), base_value: 10_u128.pow(28),
};
``` [4](#0-3) 

Because `enter_delegation_pool` only requires `amount > 0` (any non-zero amount), a delegator can enter with less than 1 STRK:

```cairo
assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
``` [5](#0-4) 

There is no function in the pool contract to rescue tokens that are not tracked in the cumulative rewards trace. `claim_rewards` only distributes what the trace records; `exit_delegation_pool_action` only returns the delegated principal. [6](#0-5) 

### Impact Explanation
Any STRK (or BTC-token) rewards forwarded to a pool whose total delegated stake is below `min_delegation_for_rewards` are permanently frozen inside the pool contract. No pool member, staker, or governance actor can recover them. This constitutes **permanent freezing of unclaimed yield**, which is a High-severity impact under the allowed scope.

### Likelihood Explanation
The minimum delegation amount is any value `> 0`. A single delegator who enters with, e.g., 0.5 STRK (below the 1 STRK threshold) creates a pool whose entire reward allocation is silently discarded each epoch. The scenario is reachable by any unprivileged delegator without any special access. For BTC pools the threshold is `10^(decimals-5)`, so the same issue applies there.

### Recommendation
The staking contract should not transfer reward tokens to a pool contract when the pool's delegated balance is below `min_delegation_for_rewards`. Concretely, before calling `send_rewards_to_delegation_pool`, the staking contract should query the pool balance and skip the transfer (and the `update_rewards_from_staking_contract` call) when `pool_balance < min_delegation_for_rewards`. Alternatively, the pool contract could return the untracked reward amount to the staking contract so it can be redistributed or held in reserve.

### Proof of Concept
1. Deploy the system with default configuration.
2. A staker stakes and enables a STRK pool.
3. A delegator calls `enter_delegation_pool` with `amount = 5 * 10^17` (0.5 STRK, below `min_for_rewards = 10^18`).
4. Advance one epoch and trigger attestation/reward distribution.
5. The staking contract computes the pool's share of rewards (`R` STRK) and calls `send_rewards_to_delegation_pool`, transferring `R` STRK to the pool contract address.
6. The staking contract then calls `pool.update_rewards_from_staking_contract(rewards=R, pool_balance=5*10^17)`.
7. Inside `compute_rewards_per_unit`: `5*10^17 < 10^18` → returns `0`; cumulative trace unchanged.
8. The delegator calls `claim_rewards` → receives `0`.
9. `R` STRK tokens remain in the pool contract with no recovery path, permanently frozen. [7](#0-6) [8](#0-7)

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
