### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Suppress Block Rewards - (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function is documented as "Only starkware sequencer" but the implementation contains no such access control. Any unprivileged caller can invoke it with `disable_rewards: true`, consuming the global `last_reward_block` slot for the current block and permanently discarding that block's rewards for the entire protocol.

---

### Finding Description

The spec explicitly states the access control for `update_rewards` is "Only starkware sequencer": [1](#0-0) 

However, the implementation's `general_prerequisites()` — the only guard called — does nothing more than check the contract is unpaused and the caller is non-zero: [2](#0-1) 

There is no `get_caller_address()` check, no role assertion, and no sequencer validation anywhere in `update_rewards`: [3](#0-2) 

The function uses a **single global** `last_reward_block` storage variable as a per-block gate. The first call in any block writes the current block number to this global, locking out all subsequent calls for that block: [4](#0-3) 

If the caller passes `disable_rewards: true`, the function writes `last_reward_block` and immediately returns — no rewards are distributed to any staker. Any subsequent call (even with `disable_rewards: false`) reverts with `REWARDS_ALREADY_UPDATED`.

---

### Impact Explanation

An attacker can front-run the legitimate sequencer call every block by calling `update_rewards(any_valid_active_staker, disable_rewards: true)`. This:

1. Consumes the block's single reward slot.
2. Distributes zero rewards to any staker.
3. Permanently discards that block's yield — it cannot be recovered retroactively.

Repeated every block, this permanently freezes all consensus block rewards for all stakers and delegators. This matches **High: Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

The function is public, requires no tokens, no stake, and no privileged role. The only cost is gas. A motivated attacker can automate this to run every block. On Starknet, where block times are short and mempool ordering is observable, front-running the sequencer's reward update is straightforward.

---

### Recommendation

Add a sequencer-only caller check at the top of `update_rewards`, consistent with the spec. For example, assert that `get_caller_address()` equals the known Starknet sequencer address (or a configured trusted address stored in contract state). This single guard closes the attack entirely.

---

### Proof of Concept

1. Deploy the staking contract with two active validators past the consensus rewards epoch.
2. From an arbitrary EOA, call `update_rewards(staker_A, disable_rewards: true)` at block N.
   - `last_reward_block` is written to N; function returns with no rewards distributed.
3. The legitimate sequencer (or anyone else) attempts `update_rewards(staker_B, disable_rewards: false)` at block N.
   - Reverts: `REWARDS_ALREADY_UPDATED` because `current_block_number > last_reward_block` is false.
4. Advance to block N+1. Repeat step 2.
5. After many blocks, observe that `unclaimed_rewards_own` for all stakers remains zero, while a model run without the attacker shows non-zero accrued rewards.

The existing test suite confirms the `REWARDS_ALREADY_UPDATED` guard fires correctly once `last_reward_block` is set, and confirms `disable_rewards: true` produces zero rewards — both behaviors are exploited here: [5](#0-4)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
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

**File:** src/staking/tests/test.cairo (L3956-3973)
```text
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    // Catch REWARDS_ALREADY_UPDATED.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());

    advance_epoch_global();
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: true);
    // Catch REWARDS_ALREADY_UPDATE - with distribute = false.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
```
