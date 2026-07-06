### Title
Unprivileged Caller Can Grief Consensus Reward Distribution via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the `Staking` contract is publicly callable with no access control. An unprivileged caller can invoke it with `disable_rewards: true` for any active staker, which unconditionally writes the global `last_reward_block` state variable to the current block **before** checking the `disable_rewards` flag. This consumes the block's single reward slot without distributing any rewards, causing every subsequent legitimate call in the same block to revert with `REWARDS_ALREADY_UPDATED`. Repeated every block, this permanently freezes all stakers' unclaimed consensus yield.

### Finding Description
`update_rewards` is part of the public `IStakingRewardsManager` interface. Its only gate is `general_prerequisites()`, which checks for pause state and a non-zero caller — no role restriction exists.

The critical ordering in the function body is:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // ← written unconditionally

if disable_rewards || self.is_pre_consensus() {
    return;                                            // ← exits without distributing
}
``` [1](#0-0) 

When called with `disable_rewards: true`, the function:
1. Validates that `current_block_number > last_reward_block` (passes on first call per block)
2. Writes `last_reward_block = current_block_number`
3. Returns immediately — no rewards are calculated or transferred

Any subsequent call to `update_rewards` in the same block fails because the assertion `current_block_number > self.last_reward_block.read()` is no longer satisfied. [2](#0-1) 

The attacker only needs to supply any currently-active staker address with non-zero STRK balance (trivially observable on-chain) to pass the staker-validity checks. [3](#0-2) 

### Impact Explanation
`last_reward_block` is a **single global slot** shared by all stakers. One attacker call per block with `disable_rewards: true` prevents every staker in the protocol from receiving their consensus block rewards for that block. Sustained over time this constitutes permanent freezing of unclaimed yield for all stakers and their delegators. This matches the allowed impact: **"Permanent freezing of unclaimed yield or unclaimed royalties; Temporary freezing of funds"** and **"Griefing with no profit motive but damage to users or protocol"**.

### Likelihood Explanation
The entry path is fully unprivileged: any non-zero address may call

### Citations

**File:** src/staking/staking.cairo (L1452-1458)
```text
            self.general_prerequisites();
            let current_block_number = starknet::get_block_number();
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
                Error::REWARDS_ALREADY_UPDATED,
            );
```

**File:** src/staking/staking.cairo (L1466-1482)
```text
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
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```
