### Title
Unprotected `disable_rewards` Parameter in `update_rewards` Allows Permanent Griefing of Block Reward Distribution — (`File: src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in `staking.cairo` is a public function with no access control. It accepts a caller-controlled `disable_rewards: bool` parameter. Because the global `last_reward_block` checkpoint is written **before** the `disable_rewards` guard is evaluated, any unprivileged caller can invoke `update_rewards(any_valid_staker, disable_rewards: true)` once per block to permanently consume the block's reward slot without distributing any rewards to stakers or pool members.

---

### Finding Description

The vulnerability class is **authorization bypass / missing access control on a reward-affecting parameter** — directly analogous to the GMX report, where a user-controlled parameter (`initialLongToken`) was accepted without validation against stored state, allowing the caller to manipulate accounting. Here, the user-controlled `disable_rewards` parameter bypasses reward distribution without any authorization check.

**Root cause — `update_rewards` in `src/staking/staking.cairo` lines 1448–1507:**

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks: not paused, caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker validity checks ...

    // ❌ Global checkpoint written BEFORE the disable_rewards guard
    self.last_reward_block.write(current_block_number);   // line ~1485

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // exits without distributing rewards
    }
    // ... reward distribution via _update_rewards ...
}
```

Key observations:

1. **No role check.** `general_prerequisites()` only asserts the contract is unpaused and the caller is non-zero. [1](#0-0) 

2. **`last_reward_block` is a single global state variable**, not per-staker. [2](#0-1) 

3. **`last_reward_block` is written before the `disable_rewards` check.** Once written, the `REWARDS_ALREADY_UPDATED` assertion blocks any other caller from distributing rewards for that block. [3](#0-2) 

4. **`staker_address` and `disable_rewards` are both caller-controlled.** The attacker can pass any valid staker address and `disable_rewards: true`. [4](#0-3) 

---

### Impact Explanation

In consensus-rewards mode, `update_rewards` is the sole mechanism for distributing per-block STRK and BTC rewards to stakers and their delegation pools. By consuming the global `last_reward_block` slot every block with `disable_rewards: true`, an attacker prevents `_update_rewards` from ever being called, meaning:

- No staker accumulates `unclaimed_rewards_own`.
- No pool contract receives rewards via `update_rewards_from_staking_contract`.
- All pool members' `cumulative_rewards_trace` stops advancing.

This constitutes **permanent freezing of unclaimed yield** for all stakers and delegators across the entire protocol.

---

### Likelihood Explanation

- **Permissionless entry point**: any EOA or contract can call `update_rewards`.
- **No capital required**: the attacker only pays Starknet gas per block.
- **Trivially automatable**: a simple script calling `update_rewards(any_active_staker, disable_rewards: true)` at every block suffices.
- **No detection or prevention mechanism** exists in the current code.

Likelihood: **High**.

---

### Recommendation

Either:

1. **Remove `disable_rewards` from the public interface** and handle the skip-rewards case internally (e.g., check `is_pre_consensus()` only inside the function, without exposing a caller-controlled bypass).
2. **Add access control** so only an authorized role (e.g., `TOKEN_ADMIN`, `APP_GOVERNOR`, or the staker themselves) can pass `disable_rewards: true`.
3. **Write `last_reward_block` only after reward distribution succeeds**, so a failed/skipped call does not consume the block slot.

---

### Proof of Concept

```
// Attacker script (pseudocode, runs every block):
loop {
    staking_contract.update_rewards(
        staker_address = any_valid_active_staker,
        disable_rewards = true
    );
    // last_reward_block is now set to current block.
    // No rewards distributed.
    // All legitimate update_rewards calls revert with REWARDS_ALREADY_UPDATED.
    wait_for_next_block();
}
```

Step-by-step:
1. Attacker calls `update_rewards(valid_staker, disable_rewards: true)` in block N.
2. `last_reward_block` is written to N before the guard check.
3. Function returns early — zero rewards distributed.
4. Any legitimate caller attempting `update_rewards` in block N receives `REWARDS_ALREADY_UPDATED`.
5. Attacker repeats in block N+1, N+2, … indefinitely.
6. All stakers and pool members permanently accumulate zero block rewards.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1451)
```text
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
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
