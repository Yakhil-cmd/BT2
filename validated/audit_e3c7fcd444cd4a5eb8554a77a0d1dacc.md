The implementation at `src/staking/staking.cairo` lines 1449–1507 contains no caller check whatsoever — only `self.general_prerequisites()` (pause check) and the `last_reward_block` gate. The spec at `docs/spec.md` line 1645 states access control is "Only starkware sequencer," but no such enforcement exists in code. There is no `only_sequencer`, `assert_sequencer`, or any sequencer-address check anywhere in the repository.

`last_reward_block` is a **global** (not per-staker) storage variable declared at line 187.

---

### Title
Missing Sequencer-Only Access Control on `update_rewards` Allows Any Caller to Permanently Suppress Block Rewards — (`src/staking/staking.cairo`)

### Summary
`update_rewards` is documented as callable only by the Starkware sequencer, but the implementation enforces no such restriction. Any unprivileged address can call it with `disable_rewards: true`, consuming the global `last_reward_block` slot for that block and permanently discarding that block's consensus rewards for all stakers.

### Finding Description
The `IStakingRewardsManager::update_rewards` function is the sole path for distributing per-block consensus rewards. Its only guards are:

1. `self.general_prerequisites()` — checks the pause flag only. [1](#0-0) 
2. `current_block_number > self.last_reward_block.read()` — a **global** one-call-per-block gate. [2](#0-1) 

After passing those checks, the function unconditionally writes `last_reward_block = current_block_number` **before** checking `disable_rewards`: [3](#0-2) 

```cairo
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;   // ← exits with no rewards distributed, slot consumed
}
```

The spec explicitly states the access control should be "Only starkware sequencer": [4](#0-3) 

No sequencer check is implemented anywhere in the codebase — `grep` for `only_sequencer`, `assert_sequencer`, or `get_sequencer` returns zero matches.

`last_reward_block` is a single global `BlockNumber` field, not per-staker: [5](#0-4) 

### Impact Explanation
An attacker who calls `update_rewards(any_valid_active_staker, disable_rewards: true)` before the sequencer in any block:
- Writes `last_reward_block` to the current block number.
- Returns immediately with zero rewards distributed.
- Causes every subsequent call in that block (including the sequencer's) to revert with `REWARDS_ALREADY_UPDATED`.

That block's rewards are **permanently lost** — there is no catch-up or retroactive distribution mechanism. Repeated across every block, this permanently freezes all unclaimed consensus yield for all stakers and their delegators.

### Likelihood Explanation
The call requires no privilege, no stake, and no special state — only a valid `staker_address` that is active and past the K-epoch activation window. On Starknet, transaction ordering within a block is controlled by the sequencer, but the sequencer cannot prevent a user transaction from being included in the same block before its own privileged call. The attacker's cost is one cheap transaction per block.

### Recommendation
Add an explicit sequencer-only caller check at the top of `update_rewards`, analogous to how `update_rewards_from_attestation_contract` checks `self.assert_caller_is_attestation_contract()`: [6](#0-5) 

Implement and call an `assert_caller_is_sequencer()` guard as the first check inside `update_rewards`, storing the authorized sequencer address in contract storage and enforcing it on every call.

### Proof of Concept
1. Deploy the staking contract with two active stakers (past K-epoch activation).
2. Advance to the first block after `consensus_rewards_first_epoch`.
3. From an arbitrary EOA, call `update_rewards(staker_A, disable_rewards: true)`.
4. Observe: `last_reward_block` is now set; the sequencer's call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeat step 3 every block.
6. After N blocks, call `claim_rewards` for both stakers — both return zero despite N blocks of eligible consensus rewards having elapsed.

The existing test `update_rewards_disable_rewards_consensus_rewards_flow_test` already demonstrates that `disable_rewards: true` with consensus active yields zero rewards and sets `last_reward_block`, confirming the mechanism. [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L187-187)
```text
        last_reward_block: BlockNumber,
```

**File:** src/staking/staking.cairo (L1399-1400)
```text
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
```

**File:** src/staking/staking.cairo (L1452-1452)
```text
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

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/flow_test/test.cairo (L2882-2895)
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
    advance_blocks(blocks: 1, block_duration: AVG_BLOCK_DURATION);
```
