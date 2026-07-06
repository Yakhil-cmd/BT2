### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Suppress Block Reward Distribution - (File: `src/staking/staking.cairo`)

### Summary

`IStakingRewardsManager::update_rewards` is documented as callable only by the Starkware sequencer, but the implementation enforces no such restriction. Any unprivileged address can call it with `disable_rewards: true`, consuming the global `last_reward_block` slot for the current block while skipping reward distribution. Because the slot is consumed first and the guard is checked after, no subsequent call in the same block can distribute rewards, permanently destroying that block's yield for all stakers and delegators.

### Finding Description

The spec explicitly states the access control for `update_rewards`:

> **access control**: Only starkware sequencer. [1](#0-0) 

The implementation, however, only calls `general_prerequisites()`, which checks that the contract is not paused and the caller is not the zero address. There is no check that the caller is the sequencer or any other privileged role: [2](#0-1) 

The critical ordering flaw is that `last_reward_block` is written **before** the `disable_rewards` branch is evaluated:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // slot consumed here

if disable_rewards || self.is_pre_consensus() {
    return;                                            // rewards skipped here
}
``` [3](#0-2) 

`last_reward_block` is a single global field shared across all stakers: [4](#0-3) 

Any subsequent call within the same block hits the `REWARDS_ALREADY_UPDATED` assertion: [5](#0-4) 

The interface definition confirms `disable_rewards` is a freely supplied boolean parameter with no restriction: [6](#0-5) 

### Impact Explanation

Once an attacker calls `update_rewards(any_valid_active_staker, disable_rewards: true)` in a block, the global `last_reward_block` is set to that block number. No legitimate sequencer call can distribute rewards for that block because the guard `current_block_number > last_reward_block` will fail. The block's yield is permanently lost for every staker and every pool member — this is **permanent freezing of unclaimed yield**.

This matches the allowed impact: **High — Permanent freezing of unclaimed yield or unclaimed royalties**.

### Likelihood Explanation

The entry path requires no funds, no role, and no prior state — any EOA or contract can call `update_rewards` on any active staker. The attacker only needs to front-run the sequencer's legitimate call within each block. On Starknet, where transaction ordering is sequencer-controlled, a determined attacker can submit this call at the start of every block to continuously suppress all consensus-era rewards across the entire protocol.

### Recommendation

Add a caller check inside `update_rewards` that restricts execution to the authorized sequencer address (or a dedicated role), consistent with the spec. The check should be placed before `last_reward_block` is written so that unauthorized calls revert without consuming the slot:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer(); // add this guard first
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
```

Alternatively, move the `last_reward_block.write` to after the `disable_rewards` branch so that a suppressed call does not consume the slot.

### Proof of Concept

1. Consensus rewards are active (`!is_pre_consensus()`).
2. Attacker (any address) calls `staking.update_rewards(valid_staker, disable_rewards: true)` at the start of block N.
3. `last_reward_block` is written to N; the function returns early without distributing rewards.
4. The legitimate sequencer attempts `staking.update_rewards(valid_staker, disable_rewards: false)` in the same block N.
5. The call reverts with `REWARDS_ALREADY_UPDATED`.
6. All stakers and pool members receive zero rewards for block N.
7. Repeat every block to permanently freeze all consensus-era yield.

The flow test suite already demonstrates that calling `update_rewards` with `disable_rewards: true` followed by a second call in the same block panics with `REWARDS_ALREADY_UPDATED`, confirming the slot-consumption behavior: [7](#0-6)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L186-187)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
```

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

**File:** src/flow_test/test.cairo (L2882-2894)
```text
    // Disable rewards = true with consensus on - no rewards
    system.update_rewards(:staker, disable_rewards: true);
    let rewards = system.staker_claim_rewards(:staker);
    assert!(rewards.is_zero());

    // Attempt again same block - panic
    let result = system
        .staking
        .rewards_manager_safe_dispatcher()
        .update_rewards(staker_address: staker.staker.address, disable_rewards: true);
    assert_panic_with_error(
        :result, expected_error: StakingError::REWARDS_ALREADY_UPDATED.describe(),
    );
```
