### Title
Unprivileged Caller Can Permanently Suppress Consensus Reward Distribution by Calling `update_rewards` with `disable_rewards=true` - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in the Staking contract updates the global `last_reward_block` state variable unconditionally — even when `disable_rewards=true` causes the function to return before distributing any rewards. Because `last_reward_block` is a global gate that allows only one reward-distribution call per block, any unprivileged caller can invoke `update_rewards(valid_staker, disable_rewards=true)` once per block to consume the reward slot without distributing rewards, permanently starving all stakers of consensus-phase yield.

### Finding Description

In `src/staking/staking.cairo`, the `update_rewards` function (part of the public `IStakingRewardsManager` interface) enforces a per-block uniqueness constraint via the global `last_reward_block` storage variable:

```cairo
// line 1453-1458
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

After all staker-validity checks pass, the function unconditionally writes the current block number to `last_reward_block` **before** branching on `disable_rewards`:

```cairo
// line 1484-1489
self.last_reward_block.write(current_block_number);  // ← always written

if disable_rewards || self.is_pre_consensus() {
    return;   // ← exits without distributing any rewards
}
```

Because `last_reward_block` is a single global field (not per-staker), a single call with `disable_rewards=true` exhausts the reward slot for the entire block for every staker. The function has no role-based access control — `general_prerequisites()` only checks that the contract is unpaused and the caller is non-zero:

```cairo
// line 1794-1797
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
```

The attacker's recipe is:
1. Identify any valid, active staker with non-zero balance (publicly readable).
2. Call `update_rewards(valid_staker, disable_rewards=true)` once per block.
3. `last_reward_block` is set to the current block; no rewards are distributed.
4. Any legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.

This is the direct analog of the external report's root cause: a global rate/state variable is modified when an action is *initiated* (here: the block's reward slot is consumed), but the modification is not undone when the action is *not actually performed* (here: `disable_rewards=true` skips distribution).

### Impact Explanation

During the consensus-rewards phase (after `consensus_rewards_first_epoch`), all staker and delegator yield accrues through `update_rewards`. If an attacker calls `update_rewards(..., disable_rewards=true)` every block, no staker ever accumulates `unclaimed_rewards_own` and no pool ever receives rewards via `update_pool_rewards`. This constitutes a **permanent freezing of unclaimed yield** for every participant in the protocol for as long as the attack is sustained. The attacker incurs only the gas cost of one transaction per block.

### Likelihood Explanation

The entry point is fully public with no access control. The only precondition is that a valid, active staker with non-zero balance exists — a condition that is always true in a live deployment. The attack requires no capital, no privileged key, and no external dependency. Any motivated adversary (competitor, griefer) can execute it continuously at minimal cost.

### Recommendation

Decouple the `last_reward_block` update from the `disable_rewards` early-exit path. Only write `last_reward_block` when rewards are actually distributed:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
// Move the write here, after the early-return guard:
self.last_reward_block.write(current_block_number);
// ... rest of reward distribution logic
```

Alternatively, restrict the `disable_rewards=true` path to a privileged caller (e.g., a security agent role), so that unprivileged callers can only invoke the function in its reward-distributing form.

### Proof of Concept

1. Consensus rewards are active (`get_current_epoch() >= consensus_rewards_first_epoch`).
2. Staker `S` is active with non-zero STRK balance.
3. Attacker `A` (any EOA) calls `update_rewards(S, disable_rewards=true)` at block `N`.
   - `last_reward_block` is written to `N` at [1](#0-0) 
   - Function returns early at [2](#0-1)  without distributing rewards.
4. Legitimate node operator calls `update_rewards(S, disable_rewards=false)` at block `N`.
   - Assertion at [3](#0-2)  fails: `N > N` is false → reverts with `REWARDS_ALREADY_UPDATED`.
5. Attacker repeats step 3 at every block. No staker ever receives consensus rewards.

The global nature of `last_reward_block` is confirmed by its storage declaration as a scalar field: [4](#0-3) 

The absence of any access control on `update_rewards` is confirmed by the sole prerequisite check: [5](#0-4)  which delegates to [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L186-187)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
```

**File:** src/staking/staking.cairo (L1452-1458)
```text
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

**File:** src/staking/staking.cairo (L1487-1489)
```text
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
