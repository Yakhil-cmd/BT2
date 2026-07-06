### Title
Unconstrained `disable_rewards` Parameter in `update_rewards` Allows Any Caller to Block Consensus Reward Distribution - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in the Staking contract is part of the public `IStakingRewardsManager` ABI and accepts a `disable_rewards: bool` parameter with no access control. Any unprivileged caller can invoke `update_rewards(any_valid_staker_address, true)` to advance the global `last_reward_block` without distributing rewards, blocking all subsequent reward updates in the same block. Repeated across every block, this permanently freezes consensus-mode yield for all stakers.

### Finding Description

`update_rewards` is exposed via `#[abi(embed_v0)]` with no caller restriction:

```cairo
// src/staking/staking.cairo  line 1448
#[abi(embed_v0)]
impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
    fn update_rewards(
        ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
    ) {
        self.general_prerequisites();                          // only checks pause flag
        let current_block_number = starknet::get_block_number();
        assert!(
            current_block_number > self.last_reward_block.read(),
            "{}",
            Error::REWARDS_ALREADY_UPDATED,
        );
        ...
        //