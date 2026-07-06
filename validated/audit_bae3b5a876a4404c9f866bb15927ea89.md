The spec declares `update_rewards` access control as "Only starkware sequencer" [1](#0-0)  but the implementation contains **no caller check whatsoever**. A grep for `sequencer` across all of `src/staking/staking.cairo` returns zero matches. The only gate is `self.general_prerequisites()`, which only checks the pause flag.

---

### Title
Missing Caller Guard on `update_rewards` Allows Any Address to Permanently Suppress Block Rewards — (`src/staking/staking.cairo`)

### Summary
`IStakingRewardsManager::update_rewards` is documented as callable only by the Starkware sequencer, but the production code enforces no such restriction. Any unprivileged address can call it with `disable_rewards: true`, consuming the global `last_reward_block` slot for that block and permanently discarding the block's consensus rewards.

### Finding Description
`update_rewards` writes `last_reward_block` to the current block number unconditionally before checking `disable_rewards`:

```
// src/staking/staking.cairo  lines 1484-1489
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // ← slot consumed here

if disable_rewards || self.is_pre_consensus() {
    return;                                            // ← rewards silently dropped
}
``` [2](#0-1) 

`last_reward_block` is a **single global** `BlockNumber` field shared across all stakers:

```
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [3](#0-2) 

The re-entry guard checks `current_block_number > self.last_reward_block.read()` and reverts with `REWARDS_ALREADY_UPDATED` if the slot is already taken: [4](#0-3) 

Once an attacker calls `update_rewards(any_valid_staker, disable_rewards: true)`, the slot for that block is consumed and no further call — including the legitimate sequencer call — can succeed in the same block.

### Impact Explanation
Every block in which the attacker fires first has its consensus rewards permanently lost. No redistribution occurs; the `unclaimed_rewards_own` of every staker is simply never incremented for that block. Repeated across many blocks this constitutes **permanent freezing of unclaimed yield** (High per the allowed impact scope).

### Likelihood Explanation
The call requires only a valid `staker_address` with non-zero effective balance (trivially readable from on-chain state) and enough gas. There is no economic barrier. An attacker can automate this to front-run the sequencer every block, suppressing 100 % of consensus rewards indefinitely.

### Recommendation
Add a sequencer-only guard at the top of `update_rewards`, consistent with the spec. For example, assert that `get_caller_address()` equals the registered sequencer address (or use the existing roles component with a dedicated `SEQUENCER` role), before any state is written.

### Proof of Concept
1. Consensus rewards are active (`!is_pre_consensus()`).
2. Staker A has effective STRK balance > 0.
3. Attacker (any EOA) calls `update_rewards(staker_A_address, disable_rewards: true)` at block N.
4. `last_reward_block` is written to N; function returns without distributing rewards.
5. Sequencer attempts `update_rewards(staker_A_address, disable_rewards: false)` at block N → reverts `REWARDS_ALREADY_UPDATED`.
6. Staker A's `unclaimed_rewards_own` is unchanged; block N rewards are gone.
7. Repeat every block: all consensus rewards are permanently suppressed.

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
