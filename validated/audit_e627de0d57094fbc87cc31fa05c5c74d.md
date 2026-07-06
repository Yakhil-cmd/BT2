### Title
Missing Caller Validation in `update_rewards` Allows Anyone to Bypass Sequencer Reward Penalization - (`File: src/staking/staking.cairo`)

### Summary

The `update_rewards` function in the staking contract is documented as callable only by the Starkware sequencer, but the implementation contains no caller validation. Any unprivileged address can call `update_rewards(staker_address, disable_rewards: false)` to distribute block rewards to a staker, even in blocks where the sequencer intended to call `update_rewards(staker_address, disable_rewards: true)` to withhold rewards due to staker misbehavior.

### Finding Description

The `IStakingRewardsManager` interface exposes `update_rewards` as a public entry point. The spec explicitly states its access control is "Only starkware sequencer": [1](#0-0) 

However, the implementation in `StakingRewardsManagerImpl` performs no such check. The function only validates that the contract is unpaused, that the block number has advanced, and that the staker is active: [2](#0-1) 

There is no `assert!(get_caller_address() == sequencer_address, ...)` or equivalent guard anywhere in the function body. Compare this to other privileged functions in the same codebase that correctly enforce caller identity, such as `update_rewards_from_attestation_contract` (which asserts the caller is the attestation contract) and `update_unclaimed_rewards_from_staking_contract` (which asserts the caller is the staking contract): [3](#0-2) 

The `disable_rewards` flag is the mechanism by which the sequencer penalizes a misbehaving staker for a given block. When `disable_rewards = true`, `last_reward_block` is updated but no rewards are minted or credited. When `disable_rewards = false` and consensus rewards are active, the function calls `_update_rewards`, which credits `staker_info.unclaimed_rewards_own` and immediately transfers pool rewards: [4](#0-3) 

Because `last_reward_block` is a global (not per-staker) variable, a single call to `update_rewards` in block N sets it to N, making any subsequent call in the same block revert with `REWARDS_ALREADY_UPDATED`. This means whichever caller reaches the function first in a given block wins.

### Impact Explanation

An attacker (who may themselves be a staker or delegator) can call `update_rewards(target_staker, disable_rewards: false)` in any block before the sequencer does. This:

1. Credits `target_staker.unclaimed_rewards_own` with block rewards the staker was not entitled to (e.g., because the staker was offline or misbehaving).
2. Immediately transfers pool rewards to the staker's delegation pool.
3. Sets `last_reward_block` to the current block, causing the sequencer's intended `update_rewards(target_staker, disable_rewards: true)` call to revert with `REWARDS_ALREADY_UPDATED`.

The staker receives yield they should not have earned. This maps to **High: Theft of unclaimed yield**.

### Likelihood Explanation

The function is publicly callable with no preconditions beyond the contract being unpaused and the staker being active. A staker or their delegator has direct financial incentive to call this every block to ensure rewards are never withheld. No privileged access, leaked keys, or external dependencies are required.

### Recommendation

Add a caller check at the top of `update_rewards` to enforce that only the authorized sequencer address can invoke it, consistent with the spec and with how other privileged callbacks in the system are protected:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    // ... rest of function
}
```

### Proof of Concept

1. Staker A is registered and active with consensus rewards enabled.
2. In block N, the sequencer determines staker A was offline and prepares to call `update_rewards(staker_A, disable_rewards: true)`.
3. Before the sequencer's transaction is included, attacker (e.g., staker A themselves, or a delegator) calls `update_rewards(staker_A, disable_rewards: false)`.
4. `last_reward_block` is set to N; staker A's `unclaimed_rewards_own` is increased by the block reward amount; pool rewards are transferred.
5. The sequencer's call reverts with `REWARDS_ALREADY_UPDATED`.
6. Staker A calls `claim_rewards(staker_A)` and receives the unauthorized rewards.

The attacker-controlled entry path is the public `IStakingRewardsManager::update_rewards` selector on the staking contract, reachable by any EOA with no preconditions beyond the staker being active. [5](#0-4) [6](#0-5)

### Citations

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1447-1508)
```text
    #[abi(embed_v0)]
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
            let current_block_number = starknet::get_block_number();
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
                Error::REWARDS_ALREADY_UPDATED,
            );

            // Assert staker exists and active.
            // Staker is considered to exist from the moment of `stake` (when `InternalStakerInfo`
            // struct is created) until the calling to `unstake_action` (when `InternalStakerInfo`
            // struct is deleted).
            // Staker remains active until the intent period begins, i.e. K epochs after
            // `unstake_intent` is called.
            let staker_info = self.internal_staker_info(:staker_address);
            let curr_epoch = self.get_current_epoch();
            assert!(
                self.is_staker_active(:staker_address, epoch_id: curr_epoch),
                "{}",
                Error::INVALID_STAKER,
            );

            let staker_pool_info = self.staker_pool_info.entry(staker_address).as_non_mut();
            let (staker_total_strk_balance, staker_total_btc_balance) = self
                .get_staker_total_strk_btc_balance_at_epoch(
                    :staker_address, :staker_pool_info, epoch_id: curr_epoch,
                );
            // Assert staker has non-zero balance.
            // Staker exists with zero balance for the first K epochs after `stake`, then the stake
            // becomes effective.
            assert!(staker_total_strk_balance.is_non_zero(), "{}", Error::INVALID_STAKER);

            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }

            // Get current block data and update rewards.
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
            let (strk_block_rewards, btc_block_rewards) = self
                .calculate_block_rewards(:reward_supplier_dispatcher, :curr_epoch);
            self
                ._update_rewards(
                    :staker_address,
                    strk_total_rewards: strk_block_rewards,
                    btc_total_rewards: btc_block_rewards,
                    strk_total_stake: staker_total_strk_balance,
                    btc_total_stake: staker_total_btc_balance,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
        }
    }
```

**File:** src/reward_supplier/reward_supplier.cairo (L189-196)
```text
        fn update_unclaimed_rewards_from_staking_contract(
            ref self: ContractState, rewards: Amount,
        ) {
            assert!(
                get_caller_address() == self.staking_contract.read(),
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );
```

**File:** src/staking/interface.cairo (L303-311)
```text
#[starknet::interface]
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```
