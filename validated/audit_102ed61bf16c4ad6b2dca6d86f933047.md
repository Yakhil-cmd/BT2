### Title
Unrestricted `update_rewards(disable_rewards: true)` Consumes Global Block-Reward Slot Without Distributing Rewards - (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract is publicly callable by any non-zero address and accepts a `disable_rewards` boolean. When called with `disable_rewards: true`, the function unconditionally writes the current block number to the global `last_reward_block` storage variable **before** checking the flag, then returns without distributing any rewards. Because `last_reward_block` gates all reward distributions for the entire protocol, any unprivileged caller can invoke this once per block to permanently prevent every staker from receiving consensus block rewards.

---

### Finding Description

`update_rewards` in `IStakingRewardsManager` has no access control beyond `general_prerequisites()`, which only checks that the contract is unpaused and the caller is non-zero. [1](#0-0) 

The function writes `last_reward_block` unconditionally, **before** the `disable_rewards` guard: [2](#0-1) 

The assertion that gates every reward update is: [3](#0-2) 

Because `last_reward_block` is a single global slot (not per-staker), writing it with `disable_rewards: true` burns the entire block's reward allocation for all stakers. No legitimate call to `update_rewards` can succeed again in that block.

The `general_prerequisites` helper confirms there is no role check:

### Citations

**File:** src/staking/staking.cairo (L1449-1452)
```text
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
```

**File:** src/staking/staking.cairo (L1454-1458)
```text
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
                Error::REWARDS_ALREADY_UPDATED,
            );
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```
