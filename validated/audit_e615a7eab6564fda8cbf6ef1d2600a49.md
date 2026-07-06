### Title
Any public caller can invoke `update_rewards` with `disable_rewards: true` to permanently freeze block rewards — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract is callable by any non-zero address with no access control. A malicious actor can call it with `disable_rewards: true` for any valid staker, consuming the block's global reward slot without distributing any rewards. Because `last_reward_block` is a global variable that is updated unconditionally before the early-return, no other call to `update_rewards` can succeed in the same block, permanently losing that block's rewards.

---

### Finding Description

`update_rewards` is exposed via `IStakingRewardsManager` with no caller restriction beyond the generic `general_prerequisites()` guard, which only checks the contract is not paused and the caller is non-zero: [1](#0-0) 

The function unconditionally writes `last_reward_block` to the current block number **before** checking `disable_rewards`: [2](#0-1) 

If `disable_rewards` is `true`, the function returns immediately without calling `_update_rewards` or `update_unclaimed_rewards_from_staking_contract` on the reward supplier: [3](#0-2) 

Because `last_reward_block` is now equal to the current block, the guard at the top of the function: [4](#0-3) 

…will cause every subsequent call to `update_rewards` in the same block to revert with `REWARDS_ALREADY_UPDATED`. The block's reward is never recorded in the reward supplier and is permanently unclaimable.

The `general_prerequisites` check that is the only gate: [5](#0-4) 

---

### Impact Explanation

For every block in which the

### Citations

**File:** src/staking/staking.cairo (L1448-1460)
```text
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
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
