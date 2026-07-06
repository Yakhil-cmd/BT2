### Title
Unprivileged Caller Can Permanently Freeze Consensus Rewards via `update_rewards(disable_rewards=true)` — (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract has no access control on its `disable_rewards` parameter. Any unprivileged caller can invoke it with `disable_rewards=true`, which unconditionally advances the global `last_reward_block` counter while skipping reward distribution. Because the function enforces a strict one-call-per-block invariant, this permanently consumes the block's reward slot and prevents the consensus mechanism from distributing rewards for that block. Rewards for skipped blocks are lost forever.

---

### Finding Description

`update_rewards` is a public function gated only by `general_prerequisites()`, which checks that the contract is not paused and the caller is not the zero address. No role check restricts who may pass `disable_rewards=true`.

The critical ordering flaw is that `last_reward_block` is written **before** the `disable_rewards` branch is evaluated:

```cairo
// src/staking/staking.cairo lines ~1484-1489
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [1](#0-0) 

`last_reward_block` is a single global `BlockNumber` (not per-staker):

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [2](#0-1) 

The one-call-per-block guard is:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [3](#0-2) 

**Analog to the Divrem chip bug:** In the report, `multiplicity = is_valid − special_case` could be

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
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
