### Title
Permissionless `update_rewards` Allows Any Caller to Permanently Freeze Staker Yield - (File: src/staking/staking.cairo)

### Summary

`IStakingRewardsManager::update_rewards` is callable by any address despite the specification requiring "Only starkware sequencer" access. Because the global `last_reward_block` is written on every successful call, an attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` first in a block permanently consumes the one allowed reward-update slot for that block, causing the legitimate sequencer call to revert with `REWARDS_ALREADY_UPDATED` and the staker to receive zero yield for that block.

### Finding Description

`update_rewards` in `StakingRewardsManagerImpl` performs no caller-identity check:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();          // only checks pause flag
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ...
    self.last_reward_block.write(current_block_number);   // global slot consumed

    if disable_rewards || self.is_pre_consensus() {
        return;                            // exits without distributing rewards
    }
    // ... reward distribution
}
``` [1](#0-0) 

`last_reward_block` is a single global storage variable, not a per-staker mapping. Exactly one call to `update_rewards` can succeed per block number. The specification explicitly states the access control should be "Only starkware sequencer": [2](#0-1) 

The `disable_rewards` flag is an attacker-controlled boolean. When set to `true`, the function writes `last_reward_block` and returns immediately without distributing any rewards: [3](#0-2) 

### Impact Explanation

An attacker who submits `update_rewards(any_valid_staker, disable_rewards: true)` before the sequencer's legitimate call in a given block:

1. Consumes the global `last_reward_block` slot for that block number.
2. Distributes zero rewards (early return due to `disable_rewards: true`).
3. Causes every subsequent `update_rewards` call in the same block to revert with `REWARDS_ALREADY_UPDATED`.

Because `calculate_block_rewards` returns a fixed per-block amount and missed blocks are simply lost (confirmed by `test_update_rewards_miss_blocks_flow_test`), each poisoned block results in permanent, irrecoverable loss of yield for all stakers. Sustained across many blocks this constitutes **permanent freezing of unclaimed yield** for all active stakers and their delegators. [4](#0-3) 

### Likelihood Explanation

The function is part of the public ABI (`#[abi(embed_v0)]`) with no caller restriction. Any address can invoke it. The attacker needs only to submit a transaction with a valid `staker_address` (any active staker) and `disable_rewards: true`. On Starknet the sequencer controls ordering, but the sequencer's `update_rewards` call is a regular transaction, not a privileged system transaction, so an attacker transaction submitted in the same block can be ordered before it. The attack requires no capital, no special role, and no external dependency — only the ability to submit transactions.

### Recommendation

Add a sequencer-only access control guard at the top of `update_rewards`, consistent with the specification. For example, store the authorized sequencer address at initialization and assert `get_caller_address() == self.sequencer_address.read()` before any state mutation. Alternatively, use the existing `RolesComponent` to define a `REWARDS_MANAGER` role restricted to the Starkware sequencer address.

### Proof of Concept

```
Block N:
  Attacker tx:   update_rewards(staker=Alice, disable_rewards=true)
                 → last_reward_block := N
                 → returns early, Alice gets 0 rewards

  Sequencer tx:  update_rewards(staker=Alice, disable_rewards=false)
                 → assert!(N > N)  ← FAILS: REWARDS_ALREADY_UPDATED
                 → Alice loses block N rewards permanently

Repeat every block → Alice (and all other stakers, since last_reward_block is global)
accumulate zero yield indefinitely.
```

The global nature of `last_reward_block` means a single attacker transaction per block is sufficient to deny rewards to every staker in the system, not just the one passed as `staker_address`. [5](#0-4) [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L1449-1489)
```text
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

**File:** src/staking/staking.cairo (L1558-1571)
```text
        fn calculate_block_rewards(
            ref self: ContractState,
            reward_supplier_dispatcher: IRewardSupplierDispatcher,
            curr_epoch: Epoch,
        ) -> (Amount, Amount) {
            if curr_epoch > self.last_calculated_epoch.read() {
                self.last_calculated_epoch.write(curr_epoch);
                let block_rewards = reward_supplier_dispatcher.update_current_epoch_block_rewards();
                self.block_rewards.write(block_rewards);
                block_rewards
            } else {
                self.block_rewards.read()
            }
        }
```

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
