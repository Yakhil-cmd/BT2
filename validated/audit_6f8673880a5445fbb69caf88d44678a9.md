### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Block Reward Distribution - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in the Staking contract specifies "Only starkware sequencer" as its access control in the protocol spec, but the implementation enforces no such restriction. Any unprivileged address can call `update_rewards` with `disable_rewards: true` to consume the global `last_reward_block` slot for the current block, permanently preventing the legitimate sequencer from distributing rewards to any staker in that block. Repeated across blocks, this constitutes a continuous, low-cost griefing attack that permanently freezes unclaimed yield.

### Finding Description

`update_rewards` is the V3 (consensus-rewards) entry point for distributing per-block staking rewards. Its only replay guard is a single **global** storage variable `last_reward_block`:

```cairo
// src/staking/staking.cairo  ~line 1453-1485
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
    // ... validate staker ...
    self.last_reward_block.write(current_block_number);   // global write
    if disable_rewards || self.is_pre_consensus() {
        return;                                           // no rewards distributed
    }
    // ... distribute rewards ...
}
```

Because `last_reward_block` is a **contract-wide** scalar (not per-staker), a single call to `update_rewards` for *any* staker in block N sets `last_reward_block = N` and makes every subsequent call in block N revert with `REWARDS_ALREADY_UPDATED`. There is no check that `get_caller_address()` is the authorised sequencer address.

The spec explicitly states the intended restriction:

> **access control**: Only starkware sequencer.

but no such check exists in the implementation.

### Impact Explanation

An attacker calls `update_rewards(victim_staker, disable_rewards: true)` at the start of every block. This:

1. Writes `last_reward_block = current_block`, consuming the one allowed slot.
2. Returns immediately without distributing any rewards (`disable_rewards = true`).
3. Causes every subsequent call by the legitimate sequencer in that block to revert with `REWARDS_ALREADY_UPDATED`.

All stakers lose their per-block consensus rewards for every block the attacker griefs. Because per-block rewards are calculated at the moment of the call and are never retroactively credited, the lost yield is **permanently unrecoverable**. This matches the allowed impact: **High — Permanent freezing of unclaimed yield**.

### Likelihood Explanation

- The function is publicly callable; no privileged role, key, or bridge is required.
- The attacker only needs to submit one cheap transaction per block (no ETH value, no token approval).
- The attack is permissionless and can be automated trivially.
- Starknet transaction fees are low, making sustained griefing economically viable.

### Recommendation

Add an explicit caller check at the top of `update_rewards` that restricts execution to the authorised sequencer address (stored in contract storage and settable by governance):

```cairo
assert!(
    get_caller_address() == self.sequencer_address.read(),
    "{}",
    Error::CALLER_IS_NOT_SEQUENCER,
);
```

Alternatively, store `last_reward_block` as a per-staker mapping (`Map<ContractAddress, BlockNumber>`) so that one attacker call cannot block all other stakers.

### Proof of Concept

1. Staker A is active and eligible for consensus rewards in block N.
2. Attacker (any address) calls `update_rewards(staker_A, disable_rewards: true)` in block N.
   - `last_reward_block` is written to N; function returns without distributing rewards.
3. The legitimate sequencer calls `update_rewards(staker_A, disable_rewards: false)` in block N.
   - Assertion `current_block_number > last_reward_block` fails → reverts with `REWARDS_ALREADY_UPDATED`.
4. Staker A receives zero rewards for block N. Repeating steps 2–4 every block permanently freezes all consensus rewards.

The existing test `update_rewards_disable_rewards_consensus_rewards_flow_test` already demonstrates that a second call in the same block reverts with `REWARDS_ALREADY_UPDATED`; the only missing piece is that the *first* call is not restricted to the sequencer. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L1449-1488)
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

**File:** docs/spec.md (L1626-1652)
```markdown
### update_rewards
```rust
fn update_rewards(ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool);
```
#### description <!-- omit from toc -->
Calculate and update the current block rewards for the for the given `staker_address`.
Send pool rewards to the pools.
Distribute rewards only if `disable_rewards` is False and consensus rewards already started.
#### emits <!-- omit from toc -->
1. [Staker Rewards Updated](#staker-rewards-updated)
2. [Rewards Supplied To Delegation Pool](#rewards-supplied-to-delegation-pool)
#### errors <!-- omit from toc -->
1. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
2. [REWARDS\_ALREADY\_UPDATED](#rewards_already_updated)
3. [STAKER\_NOT\_EXISTS](#staker_not_exists)
4. [INVALID\_STAKER](#invalid_staker)
#### pre-condition <!-- omit from toc -->
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
1. Calculate total block rewards.
2. Calculate staker rewards (include commission) and pool rewards.
3. Update `unclaimed_rewards_own` of the staker.
4. Update and transfer rewards to the pools, if exist.
5. Update Reward Supplier's `unclaimed_rewards`.
6. Update `last_reward_block` to the current block.
```

**File:** src/flow_test/test.cairo (L2822-2829)
```text
    // Attempt again same block - panic
    let result = system
        .staking
        .rewards_manager_safe_dispatcher()
        .update_rewards(staker_address: staker.staker.address, disable_rewards: true);
    assert_panic_with_error(
        :result, expected_error: StakingError::REWARDS_ALREADY_UPDATED.describe(),
    );
```
