### Title
Unprivileged Caller Can Grief Stakers by Calling `update_rewards` with `disable_rewards: true` to Consume Block Reward Slots Without Distributing Rewards - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in `StakingRewardsManagerImpl` is publicly callable by any non-zero address and accepts a caller-controlled `disable_rewards` boolean. Because `last_reward_block` is written **before** the `disable_rewards` guard is evaluated, an attacker can atomically consume a block's single reward slot while suppressing all reward distribution, permanently denying stakers their consensus block rewards for that block.

### Finding Description
`update_rewards` is exposed via `#[abi(embed_v0)]` on `StakingRewardsManagerImpl` and its only access control is `general_prerequisites()`, which checks only that the contract is unpaused and the caller is non-zero. [1](#0-0) 

The function enforces a one-call-per-block invariant by asserting `current_block_number > last_reward_block` and then immediately writing the new block number to storage: [2](#0-1) 

Only **after** that write does the code branch on `disable_rewards`: [3](#0-2) 

Because `last_reward_block` is updated unconditionally at line 1485, any subsequent legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`. An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` first in a block therefore:

1. Passes all validation (staker exists, is active, has non-zero balance).
2. Stamps `last_reward_block = current_block`.
3. Returns early — zero rewards distributed.
4. Blocks every other `update_rewards` call for that block.

The attacker needs only a valid, active staker address, which is public on-chain via the `stakers` vector and emitted events. [4](#0-3) 

### Impact Explanation
Each Starknet block carries a discrete `block_rewards` amount computed by `calculate_block_rewards`. When a block's slot is consumed with `disable_rewards: true`, those rewards are never distributed to any staker — they are not deferred or recoverable. An attacker who front-runs every block can continuously suppress all consensus reward distribution, causing permanent loss of unclaimed yield for all stakers. Even sporadic attacks cause measurable, irreversible reward loss per targeted block.

This maps to **High: Permanent freezing / theft of unclaimed yield** (rewards are computed but never credited) or at minimum **Medium: Griefing with no profit motive but damage to users or protocol**.

### Likelihood Explanation
The entry path requires no privilege, no token balance, and no special role — only a non-zero caller address and knowledge of one active staker address. Both are trivially obtained. The gas cost per block is a single transaction. The attack is therefore cheap, permissionless, and repeatable every block.

### Recommendation
1. **Remove `disable_rewards` from the public ABI.** If the protocol needs to suppress rewards during migration, handle it internally via `is_pre_consensus()` (already present) or a privileged internal call.
2. **Alternatively**, gate `update_rewards` behind a role check (e.g., `only_operator` or restrict to the staker themselves) so that only authorised callers can invoke it.
3. **At minimum**, move the `last_reward_block` write to **after** the `disable_rewards` guard so that a suppressed call does not consume the block slot:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
// Only stamp the block after confirming rewards will be distributed.
self.last_reward_block.write(current_block_number);
// ... reward calculation ...
```

### Proof of Concept

```
// Attacker script (pseudocode, runs once per block)
loop {
    wait_for_new_block();
    // any_valid_staker is any address in staking.stakers[] that is active
    staking_contract.update_rewards(
        staker_address: any_valid_staker,
        disable_rewards: true   // caller-controlled
    );
    // Result: last_reward_block = current_block, rewards = 0
    // All subsequent update_rewards calls this block revert with REWARDS_ALREADY_UPDATED
}
```

Step-by-step:
1. Block N begins. `last_reward_block` = N-1.
2. Attacker calls `update_rewards(valid_staker, disable_rewards: true)`.
3. Checks pass; `last_reward_block` is written to N; function returns early — no rewards distributed.
4. Legitimate staker calls `update_rewards(staker, disable_rewards: false)` — reverts: `current_block_number > last_reward_block` is false.
5. Block N's reward is permanently lost.
6. Repeat every block to drain all consensus reward distribution.

### Citations

**File:** src/staking/staking.cairo (L168-170)
```text
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
        /// Map token address to its decimals.
```

**File:** src/staking/staking.cairo (L1448-1486)
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

```

**File:** src/staking/staking.cairo (L1487-1507)
```text
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
```
