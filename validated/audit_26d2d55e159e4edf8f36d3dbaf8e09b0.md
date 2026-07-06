The key facts from the code:

1. **Spec says** access control is "Only starkware sequencer" [1](#0-0) 

2. **Implementation has no such check.** `general_prerequisites()` only asserts the contract is unpaused and caller is non-zero: [2](#0-1) 

3. **`last_reward_block` is a global (contract-wide) variable**, not per-staker. The guard at line 1454–1458 means only one `update_rewards` call can succeed per block, for the entire contract: [3](#0-2) 

4. **`disable_rewards: true` suppresses reward distribution** but still writes `last_reward_block`, permanently consuming the block's reward slot: [4](#0-3) 

---

### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Suppress Block Rewards — (`src/staking/staking.cairo`)

### Summary
`update_rewards` is documented as callable only by the Starkware sequencer, but the implementation enforces no such restriction. Any unprivileged address can call it with `disable_rewards: true`, consuming the global `last_reward_block` slot for that block and permanently discarding all staker rewards for that block.

### Finding Description
The `StakingRewardsManagerImpl::update_rewards` function is gated only by `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero. [5](#0-4) 

The spec explicitly states access is restricted to "Only starkware sequencer": [1](#0-0) 

The `last_reward_block` storage variable is **global** — it is shared across all stakers. Once any call to `update_rewards` succeeds in block N, the check at line 1454–1458 causes all subsequent calls in block N to revert with `REWARDS_ALREADY_UPDATED`. [3](#0-2) 

When `disable_rewards: true` is passed, the function writes `last_reward_block` to the current block and returns immediately without distributing any rewards: [4](#0-3) 

The rewards for that block are not deferred or queued — they are simply never computed or credited. The block's reward opportunity is permanently lost.

### Impact Explanation
An attacker can call `update_rewards(any_valid_active_staker, disable_rewards: true)` in every block. Each call:
- Passes all validation (staker exists, is active, has non-zero balance)
- Writes `last_reward_block = current_block`
- Returns without distributing rewards
- Blocks any legitimate sequencer call for that block

All stakers are starved of consensus rewards indefinitely. This matches **High: Permanent freezing of unclaimed yield**.

### Likelihood Explanation
The function is public with no role check. The attack requires only a valid active staker address (publicly discoverable on-chain) and a non-zero caller. It can be executed every block at minimal gas cost. No privileged access, no leaked keys, no external dependencies.

### Recommendation
Add a sequencer-only access check at the top of `update_rewards`, consistent with the spec. On Starknet, `starknet::get_execution_info().block_info.sequencer_address` can be used, or a stored sequencer address role can be enforced via the existing roles component.

### Proof of Concept
1. Deploy the staking contract with at least one active staker `S` (past the K-epoch activation window).
2. From any unprivileged address `A`, call `update_rewards(staker_address: S, disable_rewards: true)` at the start of every block.
3. Observe that `last_reward_block` is updated each block, the `REWARDS_ALREADY_UPDATED` guard blocks the legitimate sequencer call, and `S.unclaimed_rewards_own` never increases.
4. Compare cumulative rewards after N blocks: expected = N × block_reward_per_staker; actual = 0.

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
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
