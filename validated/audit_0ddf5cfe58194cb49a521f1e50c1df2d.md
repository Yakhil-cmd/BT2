### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Freeze All Stakers' Consensus Rewards — (`src/staking/staking.cairo`)

### Summary
The `update_rewards` function in the staking contract is specified as callable only by the Starkware sequencer, but no on-chain caller restriction is enforced. Because `last_reward_block` is a **global** variable that is written unconditionally before the `disable_rewards` guard, any address can call `update_rewards(staker_address: any_valid_staker, disable_rewards: true)` once per block to consume the per-block update slot without distributing any rewards, permanently preventing the sequencer from distributing consensus rewards to any staker.

### Finding Description
`update_rewards` is the sole entry point for distributing consensus-phase (V3) block rewards to stakers and their pools. Its only replay-protection is a global `last_reward_block` check:

```rust
// src/staking/staking.cairo ~L1453-1488
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks pause
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    // ← last_reward_block is written HERE, before the disable_rewards check
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // exits with NO rewards paid
    }
    ...
```

Two properties combine to create the vulnerability:

1. **No caller restriction.** `general_prerequisites()` only checks the pause flag. The spec states "Only starkware sequencer" but this is never enforced in code.
2. **`last_reward_block` is written before the `disable_rewards` guard.** Calling with `disable_rewards: true` still consumes the block's update slot, returning immediately without paying any rewards.

An attacker who submits `update_rewards(any_active_staker, disable_rewards: true)` in every block will:
- Set `last_reward_block` to the current block number.
- Cause every subsequent call in that block (including the sequencer's legitimate call) to revert with `REWARDS_ALREADY_UPDATED`.
- Distribute zero rewards to any staker.

Because the attack requires only one cheap transaction per block and is open to any address, it can be sustained indefinitely.

### Impact Explanation
All stakers and their delegators are permanently denied consensus-phase block rewards for as long as the attack is maintained. `unclaimed_rewards_own` for every staker remains at zero; pool balances receive no new tokens. This constitutes **permanent freezing of unclaimed yield** for the entire protocol.

### Likelihood Explanation
- The attacker needs no special role, no stake, and no privileged key — only a valid active staker address (publicly readable from on-chain events).
- Starknet transaction fees are low, making continuous per-block calls economically feasible.
- The attack is fully deterministic and requires no race condition or mempool manipulation.

### Recommendation
Add an explicit caller check at the top of `update_rewards` to restrict it to the authorized sequencer address (stored in contract storage or via a role):

```rust
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.roles.only_rewards_manager();   // or assert!(get_caller_address() == self.sequencer.read(), ...)
    self.general_prerequisites();
    ...
```

Alternatively, move `self.last_reward_block.write(current_block_number)` to **after** the `disable_rewards` / `is_pre_consensus` guard so that a no-op call does not consume the block slot.

### Proof of Concept

```
Given:
  - consensus rewards are active (post-consensus_rewards_first_epoch)
  - staker_A is a valid, active staker
  - attacker is any address

Each block N:
  1. Attacker calls update_rewards(staker_address: staker_A, disable_rewards: true)
     → last_reward_block is written to N
     → function returns immediately; no rewards distributed
  2. Sequencer calls update_rewards(staker_address: staker_B, disable_rewards: false)
     → assert!(N > last_reward_block.read()) fails → REWARDS_ALREADY_UPDATED revert
  3. No staker receives block rewards for block N.

Repeat for every block → all stakers' unclaimed_rewards_own remain 0 indefinitely.
``` [1](#0-0) [2](#0-1) [3](#0-2)

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
