Based on my investigation, I have found a valid analog. The `last_reward_block` storage variable in `staking.cairo` is a **global** (not per-staker) `BlockNumber`, and `update_rewards` has no access control enforcement despite the spec stating "Only starkware sequencer." Any unprivileged staker can call it, and the global lock means only one staker can receive rewards per block.

---

### Title
Global `last_reward_block` Allows Any Staker to Permanently Freeze Other Stakers' Unclaimed Yield - (File: src/staking/staking.cairo)

### Summary
`update_rewards` uses a single global `last_reward_block` variable to gate all reward distributions. Because there is no access control on the function and the lock is global rather than per-staker, any staker can call `update_rewards` for themselves once per block and permanently prevent every other staker from receiving rewards for that block.

### Finding Description
In `src/staking/staking.cairo`, the storage field `last_reward_block` is declared as a plain `BlockNumber` (not a `Map<ContractAddress, BlockNumber>`):

```
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
```

The `update_rewards` function reads and writes this single global slot:

```cairo
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
    // ... validate staker ...
    self.last_reward_block.write(current_block_number);   // global write
    // ... distribute rewards to staker_address only ...
}
```

The spec documents access control as "Only starkware sequencer," but the implementation contains **no caller check** — `general_prerequisites` only enforces the pause flag. Therefore any address, including an unprivileged staker, can invoke `update_rewards`.

Because `last_reward_block` is global, the first call in any block sets it to `current_block_number`. Every subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`, regardless of which `staker_address` is passed. With N active stakers, only one staker can receive rewards per block; the remaining N-1 stakers are silently denied their block reward with no recovery path for that block.

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

A malicious staker calls `update_rewards(attacker_address, false)` as the first transaction in every block. This:
1. Distributes that block's rewards exclusively to the attacker's staker record.
2. Sets `last_reward_block` to the current block number.
3. Causes every other staker's `update_rewards` call in the same block to revert with `REWARDS_ALREADY_UPDATED`.

Missed block rewards are never retroactively credited; the reward window for a block is permanently closed once `last_reward_block` advances. All honest stakers lose their proportional share of every block's reward indefinitely.

### Likelihood Explanation
**High.** The entry point is public with no access control. A staker with any non-zero stake has direct economic incentive: by monopolising every block's reward call they capture 100% of block rewards regardless of their actual stake proportion. The attack requires only a standard staker account and the ability to submit a transaction early in each block — no privileged key, bridge access, or external dependency is needed.

### Recommendation
Replace the global `last_reward_block: BlockNumber` with a per-staker mapping:

```cairo
last_reward_block: Map<ContractAddress, BlockNumber>,
```

Then change the guard and write in `update_rewards` to use `staker_address` as the key:

```cairo
assert!(
    current_block_number > self.last_reward_block.entry(staker_address).read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
// ...
self.last_reward_block.entry(staker_address).write(current_block_number);
```

This mirrors the fix recommended in the reference report (splitting `lastTransactionBlock` into `lastDeposit`/`lastWithdrawal`): the tracking variable must be scoped to the entity it guards, not shared globally.

Additionally, enforce the "Only starkware sequencer" access control stated in the spec to prevent unprivileged callers from invoking `update_rewards` at all.

### Proof of Concept

1. Staker A and Staker B are both active with equal stake.
2. In block N, Staker A (or any address) calls `update_rewards(staker_A_address, false)`.
   - `current_block_number (N) > last_reward_block (N-1)` → passes.
   - Staker A receives full block rewards proportional to their stake.
   - `last_reward_block` is written to `N`.
3. In the same block N, anyone calls `update_rewards(staker_B_address, false)`.
   - `current_block_number (N) > last_reward_block (N)` → **false** → reverts with `REWARDS_ALREADY_UPDATED`.
   - Staker B receives zero rewards for block N.
4. Block N advances; Staker B's block-N reward is permanently lost.
5. Repeating steps 2–4 every block permanently freezes Staker B's (and all other stakers') unclaimed yield.

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/staking/staking.cairo (L187-187)
```text
        last_reward_block: BlockNumber,
```

**File:** src/staking/staking.cairo (L1449-1458)
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
```

**File:** src/staking/staking.cairo (L1484-1485)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);
```
