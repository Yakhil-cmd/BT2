### Title
Unrestricted `disable_rewards` Parameter in Public `update_rewards` Enables Protocol-Wide Consensus Reward Griefing - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in `src/staking/staking.cairo` is publicly callable by any address and accepts a `disable_rewards: bool` parameter. When set to `true`, this parameter bypasses reward distribution while still consuming the single per-block reward slot via the **global** `last_reward_block` storage variable. An unprivileged attacker can call `update_rewards(valid_staker, disable_rewards: true)` every block to permanently prevent all stakers from receiving consensus rewards. This is structurally analogous to the external report: just as `permitSigner = address(0)` bypasses signature verification and allows anyone to exploit the system, `disable_rewards = true` bypasses reward distribution and allows anyone to freeze yield — in both cases a caller-controlled parameter disables a critical protocol check with no access control guarding the bypass path.

### Finding Description

`update_rewards` is part of `IStakingRewardsManager` and is exposed as a public ABI function via `#[abi(embed_v0)]` with no caller restriction beyond `general_prerequisites()` (not paused, caller not zero). [1](#0-0) 

The

### Citations

**File:** src/staking/staking.cairo (L1448-1490)
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

```
