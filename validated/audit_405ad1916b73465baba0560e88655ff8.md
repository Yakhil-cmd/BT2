### Title
Missing Access Control on `update_rewards` Allows Griefing to Permanently Freeze Block Reward Distribution — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract is intended to be callable only by the Starkware sequencer (per spec), but no on-chain access control is enforced. Any unprivileged caller can invoke it with `disable_rewards: true`, consuming the global `last_reward_block` slot for the current block without distributing any rewards. Because the guard is a single global variable, this permanently blocks the sequencer from distributing rewards for that block. Repeated across every block, this permanently freezes unclaimed yield for all stakers.

---

### Finding Description

`update_rewards` is the consensus-phase reward distribution entry point. Its spec explicitly states access control is "Only starkware sequencer," and its logic includes a `disable_rewards` flag intended for the sequencer to skip distribution during migrations.

The function's only guard against double-execution is a global block-number check:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [1](#0-0) 

Immediately after passing this check, `last_reward_block` is written unconditionally — before the `disable_rewards` branch:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [2](#0-1) 

There is no `assert_caller_is_sequencer()` or equivalent check anywhere in the function body. `general_prerequisites()` only checks the pause state. The test suite confirms this — `update_rewards` is called in tests without any caller spoofing: [3](#0-2) 

The spec documents the intended restriction: [4](#0-3) 

---

### Impact Explanation

An attacker calls `update_rewards(any_active_staker, disable_rewards: true)` once per block, before the sequencer. Each call:

1. Passes the `REWARDS_ALREADY_UPDATED` guard (first call in the block).
2. Writes `last_reward_block = current_block_number`.
3. Returns early — zero rewards distributed.

The sequencer's subsequent call for the same block reverts with `REWARDS_ALREADY_UPDATED`. All stakers and delegators accumulate zero unclaimed yield for that block. Sustained across every block, this constitutes **permanent freezing of unclaimed yield** for the entire protocol.

**Impact: High** — Permanent (or sustained temporary) freezing of unclaimed yield for all stakers and delegators.

---

### Likelihood Explanation

- The function is publicly callable with no on-chain access control.
- Any Starknet account can submit the transaction.
- The attacker needs only to front-run the sequencer's `update_rewards` call each block, which is straightforward since the sequencer's call is predictable.
- The attacker pays gas per block but gains no funds — pure griefing.
- The attack is trivially scriptable and can run indefinitely.

**Likelihood: High** — No special privilege required; any account can execute it.

---

### Recommendation

Add an explicit caller check at the top of `update_rewards`, analogous to the check already present in `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(...) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer(); // add this
    ...
}
```

Alternatively, enforce the restriction via a role (e.g., `REWARDS_MANAGER_ROLE`) and gate the function with `self.roles.only_rewards_manager()`.

---

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns false).
2. Attacker (any EOA) calls `update_rewards(staker_A, disable_rewards: true)` at block N.
3. `last_reward_block` is set to N; no rewards distributed.
4. Sequencer calls `update_rewards(staker_A, disable_rewards: false)` at block N → reverts with `REWARDS_ALREADY_UPDATED`.
5. Staker A and all delegators receive zero rewards for block N.
6. Attacker repeats step 2 at block N+1, N+2, … indefinitely.
7. `unclaimed_rewards_own` for all stakers remains zero; `RewardSupplier.unclaimed_rewards` is never incremented; delegator pool balances never grow.

The root cause is the missing access control on `update_rewards` at: [5](#0-4) 

combined with the unconditional `last_reward_block` write at: [2](#0-1)

### Citations

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

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

**File:** src/flow_test/test.cairo (L2818-2829)
```text
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
```

**File:** docs/spec.md (L1643-1652)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
1. Calculate total block rewards.
2. Calculate staker rewards (include commission) and pool rewards.
3. Update `unclaimed_rewards_own` of the staker.
4. Update and transfer rewards to the pools, if exist.
5. Update Reward Supplier's `unclaimed_rewards`.
6. Update `last_reward_block` to the current block.
```
