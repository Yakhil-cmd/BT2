### Title
Griefing via `update_rewards` with `disable_rewards=true` Permanently Freezes Block Rewards - (File: src/staking/staking.cairo)

### Summary

The public `update_rewards` function in `staking.cairo` writes to the global `last_reward_block` storage variable **before** checking the `disable_rewards` flag. Any unprivileged caller can invoke `update_rewards(any_active_staker, true)` once per block to "consume" the block's reward slot without distributing any rewards, permanently preventing legitimate reward distribution for that block.

### Finding Description

`update_rewards` is a public, permissionless function in `IStakingRewardsManager`. Its purpose in the consensus rewards phase is to distribute per-block STRK/BTC rewards to a staker. The function enforces a single-call-per-block invariant via a global `last_reward_block` storage variable: [1](#0-0) 

The critical ordering flaw is here: [2](#0-1) 

`last_reward_block.write(current_block_number)` executes at line ~1485, **before** the `disable_rewards` branch at line ~1487. This means:

1. An attacker calls `update_rewards(any_active_staker, true)` as the first transaction in a block.
2. The check `current_block_number > last_reward_block` passes (first call this block).
3. `last_reward_block` is updated to `current_block_number`.
4. The function returns early due to `disable_rewards = true` — **no rewards are distributed**.
5. Every subsequent legitimate call to `update_rewards` in the same block fails with `REWARDS_ALREADY_UPDATED`.

The `last_reward_block` is a **single global variable**, not per-staker: [3](#0-2) 

So one attacker transaction per block griefs **all stakers** simultaneously.

### Impact Explanation

In the consensus rewards phase (`is_pre_consensus() == false`), `update_rewards` is the sole mechanism for distributing per-block rewards. There is no retroactive catch-up mechanism — if `update_rewards` is not called with `disable_rewards=false` in a given block, those block rewards are permanently unclaimable by stakers. Continuous griefing (one cheap tx per block) results in **permanent freezing of all unclaimed block-level yield** for the entire protocol.

This matches the allowed impact: **High — Permanent freezing of unclaimed yield**.

### Likelihood Explanation

- The function is fully permissionless; any address can call it.
- The attacker only needs to know one active staker address (trivially available from on-chain `NewStaker` events).
- The cost is one transaction per block on Starknet (low fee environment).
- No profit motive is required; pure griefing is sufficient.
- The attack is mechanically simple and requires no special setup.

### Recommendation

Move `last_reward_block.write(current_block_number)` to **after** the `disable_rewards` guard, so that a call with `disable_rewards=true` does not consume the block's reward slot:

```cairo
// Update last block rewards ONLY when actually distributing.
if disable_rewards || self.is_pre_consensus() {
    return;
}

// Only now mark the block as processed.
self.last_reward_block.write(current_block_number);

// ... distribute rewards ...
```

Alternatively, separate the "mark block processed" logic from the "distribute rewards" logic, or restrict who can call `update_rewards` with `disable_rewards=true`.

### Proof of Concept

1. The protocol is in the consensus rewards phase (`consensus_rewards_first_epoch` has been set and passed).
2. Attacker observes any active staker address `S` from on-chain events.
3. At the start of every block, attacker submits: `update_rewards(S, disable_rewards=true)`.
4. This sets `last_reward_block = current_block` without distributing any rewards.
5. The legitimate sequencer/keeper call `update_rewards(S, false)` in the same block fails: `assert!(current_block_number > self.last_reward_block.read(), ...)` → `REWARDS_ALREADY_UPDATED`.
6. All stakers receive zero block rewards for every griefed block. Since there is no retroactive distribution mechanism, these rewards are permanently lost. [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1490)
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
