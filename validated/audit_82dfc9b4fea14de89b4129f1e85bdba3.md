### Title
Global `last_reward_block` Shared Across All Stakers Allows Any Caller to Block Reward Distribution for Other Stakers - (File: `src/staking/staking.cairo`)

### Summary
The `update_rewards` function uses a single global `last_reward_block` storage variable to gate reward distribution. Because this variable is shared across all stakers and is updated on the first call within a block, any subsequent call for a different staker in the same block reverts with `REWARDS_ALREADY_UPDATED`. Combined with the absence of an enforced "only sequencer" access control guard, any unprivileged caller can invoke `update_rewards` for one staker at the start of every block, permanently preventing all other stakers from ever receiving their consensus block rewards.

### Finding Description
`update_rewards` in `src/staking/staking.cairo` performs the following sequence:

```
fn update_rewards(ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool) {
    self.general_prerequisites();                          // only checks pause flag
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),  // global gate
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    self.last_reward_block.write(current_block_number);    // global write
    ...
}
```

`last_reward_block` is declared as a single scalar in contract storage:

```
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
```

It is not keyed by `staker_address`. The first call to `update_rewards` at block `N` (for any staker) writes `last_reward_block = N`. Every subsequent call at block `N` (for any other staker) fails the assertion `current_block_number > last_reward_block` because `N > N` is false.

The spec documents the intended access control as "Only starkware sequencer," but the implementation only calls `self.general_prerequisites()`, which enforces only the pause flag. There is no `only_sequencer` or equivalent role check in the function body. This means any externally-owned address can call `update_rewards`.

### Impact Explanation
An attacker calls `update_rewards(victim_staker, false)` as the first transaction of every block. This:
1. Legitimately distributes rewards to `victim_staker` for that block (no theft).
2. Sets `last_reward_block` to the current block number.
3. Causes every subsequent `update_rewards` call for any other staker in the same block to revert with `REWARDS_ALREADY_UPDATED`.

If repeated every block, all stakers except the one chosen by the attacker are permanently frozen out of consensus block rewards. Their `unclaimed_rewards_own` is never incremented. The lost rewards are not recoverable — there is no catch-up mechanism for missed blocks.

This matches the allowed impact: **High — Permanent freezing of unclaimed yield**.

### Likelihood Explanation
- The entry point is fully public; no token balance, stake, or privileged role is required.
- The attacker only needs to submit a transaction before the sequencer's own `update_rewards` call each block.
- The cost is gas only. The attacker can target any staker they wish to freeze.
- The attack is sustainable indefinitely.

### Recommendation
1. **Track `last_reward_block` per staker**: Change the storage variable from a scalar to a map keyed by staker address:
   ```
   last_reward_block: Map<ContractAddress, BlockNumber>,
   ```
   Update the read/write sites accordingly so each staker's reward gate is independent.

2. **Enforce the intended access control**: Add an explicit sequencer-only check at the top of `update_rewards` to match the specification, preventing unprivileged callers from invoking the function at all.

### Proof of Concept
1. Stakers A, B, and C are all active with non-zero balances.
2. At block 1000, attacker (any address) calls `update_rewards(staker_A, false)`.
   - `last_reward_block` is written to `1000`.
   - Staker A receives block 1000 rewards.
3. Sequencer attempts `update_rewards(staker_B, false)` at block 1000.
   - Assert `1000 > 1000` fails → reverts with `REWARDS_ALREADY_UPDATED`.
   - Staker B receives no rewards for block 1000.
4. Sequencer attempts `update_rewards(staker_C, false)` at block 1000.
   - Same revert. Staker C receives no rewards for block 1000.
5. Attacker repeats step 2 at every subsequent block.
   - Stakers B and C permanently accumulate zero consensus rewards.

**Root cause lines:** [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/staking/staking.cairo (L186-187)
```text
        /// Last block number for which rewards were distributed.
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
