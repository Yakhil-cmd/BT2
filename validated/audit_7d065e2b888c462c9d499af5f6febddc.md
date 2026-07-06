### Title
Missing Sequencer-Only Access Control Allows Any Caller to Suppress Block Rewards — (`src/staking/staking.cairo::update_rewards`)

---

### Summary

`update_rewards` is documented as "Only starkware sequencer" but the implementation enforces no such restriction. Any unprivileged caller can invoke it first in any block with `disable_rewards = true`, permanently consuming the global `last_reward_block` gate for that block and causing the legitimate sequencer call to revert with `REWARDS_ALREADY_UPDATED`. The block's consensus rewards are irrecoverably lost.

---

### Finding Description

The spec explicitly states the access control for `update_rewards`:

> **access control**: Only starkware sequencer. [1](#0-0) 

The actual implementation's only guard is `general_prerequisites()`:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [2](#0-1) 

There is no sequencer identity check anywhere in `update_rewards`. The function then proceeds to write `last_reward_block` — a **global** (single, non-per-staker) storage variable — **before** the `disable_rewards` branch:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [3](#0-2) 

The `last_reward_block` field is declared as a single global `BlockNumber`:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [4](#0-3) 

The block-gate check at the top of the function is:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [5](#0-4) 

Because `last_reward_block` is global and is written unconditionally before the `disable_rewards` early-return, a single attacker call with `disable_rewards = true` permanently exhausts the reward slot for the entire block. Any subsequent call — including the legitimate sequencer call — reverts with `REWARDS_ALREADY_UPDATED`.

---

### Impact Explanation

The attacker can call `update_rewards(any_valid_staker_address, disable_rewards: true)` at the start of every block. Each such call:

1. Passes `general_prerequisites()` (contract is unpaused, caller is non-zero).
2. Passes the `last_reward_block` gate (new block, so `current_block_number > last_reward_block`).
3. Writes `last_reward_block = current_block_number`.
4. Returns early — no rewards distributed.

The sequencer's intended call then fails with `REWARDS_ALREADY_UPDATED`. The block's consensus rewards are permanently discarded. Repeated across every block, this permanently freezes all unclaimed yield for all stakers.

**Impact**: High — Permanent freezing of unclaimed yield.

---

### Likelihood Explanation

The function is publicly callable by any non-zero address with no economic barrier. The attacker only needs to submit a transaction before the sequencer's reward update in each block. On Starknet, transaction ordering within a block is controlled by the sequencer, which complicates front-running — however, the sequencer itself could be the attacker, or the attacker could exploit any block where the sequencer has not yet submitted the reward update. The spec/implementation mismatch is a clear missing access control, not a theoretical edge case.

---

### Recommendation

Add a sequencer-only caller check inside `update_rewards` (or inside a dedicated prerequisite), consistent with the spec. For example, assert that `get_caller_address() == expected_sequencer_address`, where the sequencer address is stored in contract configuration. This is the same pattern used for other privileged operations in the contract.

---

### Proof of Concept

```
1. Deploy staking contract with consensus rewards active.
2. Stake as staker_A (valid, active staker with non-zero STRK balance).
3. Advance to a new block.
4. Attacker (any EOA) calls:
       update_rewards(staker_address: staker_A, disable_rewards: true)
   → succeeds; last_reward_block = current_block
5. Sequencer calls:
       update_rewards(staker_address: staker_A, disable_rewards: false)
   → reverts with REWARDS_ALREADY_UPDATED
6. staker_A.unclaimed_rewards_own is unchanged — block reward permanently lost.
7. Repeat step 3–6 for every block → all consensus rewards permanently suppressed.
```

The existing test suite already demonstrates the `REWARDS_ALREADY_UPDATED` revert behavior when called twice in the same block: [6](#0-5) 

and confirms that `disable_rewards = true` produces zero rewards: [7](#0-6)

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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/staking/tests/test.cairo (L3878-3884)
```text
    // Catch REWARDS_ALREADY_UPDATED.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
```

**File:** src/flow_test/test.cairo (L2785-2788)
```text
    // Call update_rewards with disable rewards = true - no rewards
    system.update_rewards(:staker, disable_rewards: true);
    let rewards = system.staker_claim_rewards(:staker);
    assert!(rewards == Zero::zero());
```
