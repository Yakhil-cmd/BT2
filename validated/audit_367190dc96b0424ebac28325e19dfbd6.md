### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Deny Block Rewards - (`File: src/staking/staking.cairo`)

---

### Summary

`update_rewards` in `src/staking/staking.cairo` is specified to be callable only by the Starknet sequencer, but the implementation contains no caller check. Any unprivileged address can call it with `disable_rewards: true`, consuming the single per-block reward slot without distributing any rewards. Because `last_reward_block` is a global variable, the sequencer's subsequent legitimate call for the same block reverts with `REWARDS_ALREADY_UPDATED`, permanently destroying the block's yield for all stakers and delegators.

---

### Finding Description

The specification at `docs/spec.md` line 1645 states:

> **access control**: Only starkware sequencer.

The implementation at `src/staking/staking.cairo` lines 1449–1507 is:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();   // only checks: not paused, caller != zero
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ...
    self.last_reward_block.write(current_block_number);   // global, not per-staker

    if disable_rewards || self.is_pre_consensus() {
        return;   // exits without distributing any rewards
    }
    // ... distribute rewards
}
```

`general_prerequisites` (lines 1794–1797) only asserts the contract is unpaused and the caller is non-zero — there is no sequencer identity check:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
```

`last_reward_block` is a single global storage slot (not keyed per staker). The guard `current_block_number > self.last_reward_block.read()` means only one call per block can succeed. An attacker who calls `update_rewards(valid_staker, disable_rewards: true)` first in any block:

1. Passes all checks (contract unpaused, staker exists and active, non-zero balance).
2. Writes `last_reward_block = current_block_number`.
3. Returns immediately at the `disable_rewards` branch — zero rewards distributed.
4. The sequencer's legitimate call for the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. The block's rewards are permanently unrecoverable.

---

### Impact Explanation

Every block in which the attacker fires this call before the sequencer's `update_rewards` transaction results in **permanent loss of that block's inflationary yield** for all stakers and their delegators. The rewards are never minted/transferred; they are simply skipped. This matches the allowed impact: **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

The entry point is fully public — any non-zero address can call it. The attacker only needs to submit a transaction in a block where the sequencer has not yet called `update_rewards`. Because the sequencer may not call `update_rewards` in every block (the spec's precondition is "rewards did not distribute for the current block yet", implying it is not guaranteed every block), there are windows where the attacker can act. Even if the sequencer calls it in most blocks, a sustained griefing campaign can target any missed block. No funds, keys, or privileged roles are required.

---

### Recommendation

Add a sequencer-only caller check inside `update_rewards`, consistent with the spec. For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    // ... rest of function
}
```

Alternatively, if a dedicated sequencer address is not stored, use Starknet's `get_sequencer_address()` syscall to validate the caller.

---

### Proof of Concept

**Setup:**
- Consensus rewards are active (post `set_consensus_rewards_first_epoch`).
- A valid staker exists with non-zero balance effective for the current epoch.

**Attack steps:**

1. Attacker (any address) calls:
   ```
   update_rewards(staker_address: valid_staker, disable_rewards: true)
   ```
   in block N, before the sequencer's transaction.

2. Inside `update_rewards`:
   - `general_prerequisites()` passes (contract unpaused, attacker ≠ zero).
   - `current_block_number (N) > last_reward_block` passes.
   - `last_reward_block` is written to N.
   - `disable_rewards = true` → function returns with no rewards distributed.

3. Sequencer attempts:
   ```
   update_rewards(staker_address: valid_staker, disable_rewards: false)
   ```
   in the same block N.

4. The assert `current_block_number > self.last_reward_block.read()` evaluates as `N > N` → **false** → reverts with `REWARDS_ALREADY_UPDATED`.

5. Block N's inflationary STRK rewards for the staker and all delegators are permanently lost.

**Relevant code locations:**

- Missing caller check: [1](#0-0) 
- `general_prerequisites` (no sequencer check): [2](#0-1) 
- Global `last_reward_block` write: [3](#0-2) 
- Spec access control requirement ("Only starkware sequencer"): [4](#0-3)

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

**File:** src/staking/staking.cairo (L1794-1797)
```text
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
