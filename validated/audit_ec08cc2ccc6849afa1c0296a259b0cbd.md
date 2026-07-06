### Title
Missing Sequencer Access Control on `update_rewards` Allows Any Caller to Permanently Suppress Block Rewards — (`src/staking/staking.cairo`)

---

### Summary

`update_rewards` is specified as callable only by the Starkware sequencer, but the implementation enforces no such restriction. Any unprivileged address can call it with `disable_rewards: true`, which writes the global `last_reward_block` to the current block and returns early — permanently consuming that block's reward slot for every staker.

---

### Finding Description

The spec explicitly states:

> **access control**: Only starkware sequencer. [1](#0-0) 

The implementation's `general_prerequisites()` enforces only two things: the contract is not paused, and the caller is not the zero address. [2](#0-1) 

There is no sequencer identity check anywhere in `update_rewards` or its prerequisites.

Inside `update_rewards`, the critical ordering is:

1. Check `current_block_number > last_reward_block` — passes on any new block.
2. **Write `last_reward_block = current_block_number`** — permanently marks this block as "done."
3. If `disable_rewards == true`, **return immediately** without distributing any rewards. [3](#0-2) 

`last_reward_block` is a single **global** `BlockNumber` storage slot shared across all stakers — not per-staker. [4](#0-3) 

Any subsequent call to `update_rewards` for the same block number — including the legitimate sequencer call — will revert with `REWARDS_ALREADY_UPDATED`: [5](#0-4) 

---

### Impact Explanation

An attacker who front-runs every block with `update_rewards(any_active_staker, disable_rewards: true)` permanently discards that block's rewards for all stakers. The rewards are never minted/distributed; they are simply skipped. This matches **High: Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

The call is permissionless, costs only gas, and requires no capital. On Starknet, transaction ordering within a block is sequencer-controlled, but the attacker only needs to submit the transaction before the sequencer's own `update_rewards` call lands. Because the function is public and the sequencer's call is predictable (one per block), a griefing bot can sustain this indefinitely.

---

### Recommendation

Add a sequencer-only access control guard to `update_rewards`, consistent with the spec. For example, check `get_caller_address() == sequencer_address` where `sequencer_address` is a stored, governance-controlled value, or use an existing role from the `RolesComponent` already present in the contract. [6](#0-5) 

---

### Proof of Concept

1. Deploy the staking contract with two active stakers, both past the K-epoch activation window, with consensus rewards enabled.
2. On each new block, before the sequencer acts, submit: `update_rewards(staker_A, disable_rewards: true)`.
3. Observe that `last_reward_block` is now equal to the current block.
4. The sequencer's subsequent `update_rewards(staker_A, disable_rewards: false)` reverts with `REWARDS_ALREADY_UPDATED`.
5. After N blocks, call `claim_rewards` for both stakers and observe zero accumulated rewards, versus the expected non-zero amount from the reward model.

The existing test suite already confirms the `REWARDS_ALREADY_UPDATED` revert behavior when the same block is called twice: [7](#0-6) 

— demonstrating that the gate is real and that a prior call with `disable_rewards: true` blocks any subsequent call with `disable_rewards: false` on the same block.

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

**File:** src/staking/staking.cairo (L1453-1458)
```text
            let current_block_number = starknet::get_block_number();
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

**File:** src/staking/staking.cairo (L1794-1797)
```text
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/staking/tests/test.cairo (L3878-3884)
```text
    // Catch REWARDS_ALREADY_UPDATED.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
```
