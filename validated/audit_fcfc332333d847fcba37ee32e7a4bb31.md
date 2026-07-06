### Title
Unconstrained `disable_rewards` Flag in `update_rewards` Allows Permanent Freezing of Per-Block Yield — (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract is callable by any unprivileged actor and accepts a `disable_rewards` boolean parameter. When set to `true`, the function writes the current block number into the global `last_reward_block` storage slot **without distributing any rewards**. Because there is no authorization check on who may invoke this function or set this flag, any actor can permanently consume a block's reward slot — causing the legitimate block-proposer's subsequent call to revert with `REWARDS_ALREADY_UPDATED` and the epoch rewards for that block to be irrecoverably lost.

---

### Finding Description

`update_rewards` is gated only by `general_prerequisites`, which checks that the contract is not paused and that the caller is non-zero:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [1](#0-0) 

After validating that the staker exists and has non-zero balance, the function unconditionally advances the global `last_reward_block` and then branches on `disable_rewards`:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [2](#0-1) 

The guard that prevents a second call in the same block is:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [3](#0-2) 

Because `last_reward_block` is a **single global slot** (not per-staker), any actor who calls `update_rewards(any_active_staker, disable_rewards: true)` first in a given block will:

1. Advance `last_reward_block` to the current block.
2. Return immediately without distributing rewards.
3. Cause every subsequent call in that block to revert with `REWARDS_ALREADY_UPDATED`.

The rewards that should have been distributed for that block are permanently lost — there is no mechanism to retroactively credit them.

The analog to the external report is direct: just as the `is_buffer_start` flag was supposed to be a required constraint activating the execution-bridge connection but was never enforced, the `disable_rewards` flag is supposed to be an internal signal used only in controlled circumstances (e.g., staker removal), but the absence of any caller restriction means an adversary can set it freely to bypass the reward-distribution path.

---

### Impact Explanation

**Permanent freezing of unclaimed yield.** Every block in the consensus-rewards phase (`!is_pre_consensus()`) carries a STRK reward allocation for the active staker. An attacker who calls `update_rewards(valid_staker, disable_rewards: true)` before the legitimate proposer in block N causes the entire block-N reward to be silently dropped. Repeated across many blocks, this constitutes a sustained, low-cost denial of yield to all stakers and their delegators.

---

### Likelihood Explanation

High. The function is fully public; the only precondition is a non-zero caller and a valid active staker address (trivially discoverable on-chain via the `stakers` vector and `staker_info` map). No privileged key, bridge access, or token-admin role is required. The attack is a single transaction per block and costs only gas.

---

### Recommendation

Restrict `update_rewards` to an authorized caller (e.g., a dedicated `REWARDS_MANAGER` role, or the block proposer's operational address). Alternatively, remove the `disable_rewards` parameter from the public interface and handle the "no-reward" path internally based on on-chain state (e.g., `is_pre_consensus()` or zero balance), so that no external actor can influence whether rewards are distributed for a given block.

---

### Proof of Concept

1. Consensus rewards are active (`!is_pre_consensus()`).
2. Attacker identifies any active staker `S` with non-zero STRK balance.
3. In block `N`, attacker submits `update_rewards(S, disable_rewards: true)`.
4. `last_reward_block` is set to `N`; no rewards are distributed.
5. The legitimate block-proposer submits `update_rewards(S, disable_rewards: false)` in the same block `N`.
6. The call reverts: `current_block_number (N) > last_reward_block (N)` is false → `REWARDS_ALREADY_UPDATED`.
7. Block `N`'s reward is permanently lost for all stakers and delegators.

The attacker repeats this every block at negligible cost, continuously suppressing yield across the entire protocol.

### Citations

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
