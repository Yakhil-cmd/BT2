The key facts from the code are decisive here.

**Access control in `general_prerequisites`** (the only guard called before the reward logic): [1](#0-0) 

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
```

There is **no sequencer/role check**. The spec at line 1645 says "Only starkware sequencer" but the implementation enforces nothing beyond "caller != zero address."

**`last_reward_block` is a single global slot** (not per-staker): [2](#0-1) 

**The critical ordering in `update_rewards`**: `last_reward_block` is written **before** the `disable_rewards` branch: [3](#0-2) 

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
```

The `REWARDS_ALREADY_UPDATED` guard prevents any second call in the same block: [4](#0-3) 

---

### Title
Missing Caller Authorization in `update_rewards` Allows Any Address to Permanently Suppress Per-Block Rewards — (`src/staking/staking.cairo`)

### Summary
`update_rewards` has no sequencer/role guard. Any non-zero address can call it first in any block with `disable_rewards: true`, consuming the global `last_reward_block` slot without distributing rewards. All subsequent legitimate calls for that block revert with `REWARDS_ALREADY_UPDATED`, permanently discarding that block's yield for every staker.

### Finding Description
`general_prerequisites()` only asserts the contract is unpaused and the caller is non-zero. [5](#0-4) 

The spec mandates "Only starkware sequencer" access control: [6](#0-5) 

Because `last_reward_block` is a single global value written unconditionally before the `disable_rewards` branch, a hostile caller who wins the race for block N writes `last_reward_block = N` and returns early. The sequencer's legitimate call for block N then hits `REWARDS_ALREADY_UPDATED` and reverts. [3](#0-2) 

### Impact Explanation
Every block where the attacker front-runs the sequencer call with `disable_rewards: true` produces zero rewards for all stakers. The block's reward opportunity is permanently gone — there is no catch-up mechanism. Sustained griefing across many blocks constitutes permanent freezing of unclaimed yield.

**Impact: High — Permanent freezing of unclaimed yield.**

### Likelihood Explanation
The attacker needs only to submit a transaction before the sequencer's `update_rewards` call each block. On Starknet, transaction ordering within a block is controlled by the sequencer, which limits the practical exploitability — the sequencer can order its own `update_rewards` call first. However, the missing access control is a concrete code-level vulnerability that violates the stated invariant and could be exploited if the sequencer's ordering guarantee is ever weakened or if the sequencer itself is adversarial.

### Recommendation
Add a sequencer/operator role check inside `update_rewards` (or inside `general_prerequisites` for this function), consistent with the spec's stated "Only starkware sequencer" access control. For example, assert `get_caller_address() == sequencer_address` or use the existing roles component to gate the call.

### Proof of Concept
1. Deploy the staking contract with two active stakers past the K-epoch activation window and with consensus rewards enabled.
2. At the start of block N, submit a transaction from an arbitrary EOA calling `update_rewards(any_valid_staker, disable_rewards: true)`.
3. Observe: `last_reward_block` is set to N, no rewards are distributed.
4. The sequencer's legitimate `update_rewards` call for block N reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeat for every block. Both stakers accumulate zero rewards indefinitely despite being fully active.

### Citations

**File:** src/staking/staking.cairo (L186-187)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
