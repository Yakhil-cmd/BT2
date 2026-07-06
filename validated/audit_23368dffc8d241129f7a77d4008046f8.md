### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Suppress Block Rewards — (`src/staking/staking.cairo`)

### Summary

The spec mandates "Only starkware sequencer" access control for `update_rewards`, but the implementation contains **no caller check**. Any unprivileged address can call it. Combined with a **global** (not per-staker) `last_reward_block` gate, an attacker can front-run the sequencer each block, pass `disable_rewards: true`, permanently consume the block's reward slot, and cause the legitimate sequencer call to revert — permanently destroying that block's yield for the targeted staker.

---

### Finding Description

The spec explicitly states:

> **access control**: Only starkware sequencer. [1](#0-0) 

The implementation, however, performs no such check. The only guards inside `update_rewards` are:

1. `self.general_prerequisites()` — checks only the pause flag.
2. `current_block_number > self.last_reward_block.read()` — a **global**, single-slot block gate. [2](#0-1) 

There is no `get_caller_address()` comparison, no role check, and no sequencer address validation anywhere in the function or in `general_prerequisites`. A grep for `sequencer` across all Cairo source files returns zero matches.

The `last_reward_block` field is a single global `BlockNumber` stored in contract state: [3](#0-2) 

It is written unconditionally before the `disable_rewards` branch: [4](#0-3) 

This means: **one call per block, for any staker, by any caller, permanently consumes the block's reward slot for the entire protocol.**

---

### Impact Explanation

An attacker executes the following each block:

1. Calls `update_rewards(victim_staker_address, disable_rewards: true)` before the sequencer.
2. The function passes all checks (staker is active, balance is non-zero, block is new).
3. `last_reward_block` is written to the current block number.
4. The `disable_rewards: true` branch is taken — no rewards are distributed.
5. The sequencer's legitimate call for the same block reverts with `REWARDS_ALREADY_UPDATED`.

The block's rewards are **permanently lost** — there is no catch-up mechanism, no retry window, and no way to re-attribute a skipped block's yield. The `calculate_block_rewards` path is simply never reached. [5](#0-4) 

Impact: **High — Permanent freezing of unclaimed yield**, matching the allowed scope.

---

### Likelihood Explanation

- Requires no funds, no stake, no privileged role — any EOA can call it.
- The attacker only needs to submit a transaction earlier in the block than the sequencer's `update_rewards` call.
- On Starknet, transaction ordering within a block is controlled by the sequencer, but the sequencer is the *same entity* that is supposed to call this function. An external attacker submitting a transaction to the mempool can race the sequencer's own system transaction. If the sequencer does not enforce that its reward-update transaction is always first, the attack is trivially repeatable every block.
- The test suite itself calls `update_rewards` from arbitrary test addresses with no special role setup, confirming the absence of any access gate: [6](#0-5) 

---

### Recommendation

Add a caller check at the top of `update_rewards` that asserts `get_caller_address() == <sequencer_address>` (or a stored, governance-controlled sequencer role). The spec already defines the intended restriction; it simply was not implemented.

---

### Proof of Concept

```
// Block N:
// Attacker (any address) calls:
staking.update_rewards(victim_staker, disable_rewards: true);
// → last_reward_block = N, no rewards distributed

// Sequencer then calls (same block N):
staking.update_rewards(victim_staker, disable_rewards: false);
// → PANICS: REWARDS_ALREADY_UPDATED (current_block_number == last_reward_block)

// Victim staker's unclaimed_rewards_own is unchanged.
// Block N's yield is permanently lost.
```

The existing flow test at line 2786 already demonstrates that `disable_rewards: true` produces zero rewards and that a second call in the same block panics — the only missing piece is that the *first* caller is supposed to be the sequencer, not an arbitrary address. [7](#0-6)

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

**File:** src/staking/staking.cairo (L1484-1507)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }

            // Get current block data and update rewards.
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
            let (strk_block_rewards, btc_block_rewards) = self
                .calculate_block_rewards(:reward_supplier_dispatcher, :curr_epoch);
            self
                ._update_rewards(
                    :staker_address,
                    strk_total_rewards: strk_block_rewards,
                    btc_total_rewards: btc_block_rewards,
                    strk_total_stake: staker_total_strk_balance,
                    btc_total_stake: staker_total_btc_balance,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
        }
```

**File:** src/staking/tests/test.cairo (L3956-3960)
```text
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    // Catch REWARDS_ALREADY_UPDATED.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
```

**File:** src/flow_test/test.cairo (L2785-2788)
```text
    // Call update_rewards with disable rewards = true - no rewards
    system.update_rewards(:staker, disable_rewards: true);
    let rewards = system.staker_claim_rewards(:staker);
    assert!(rewards == Zero::zero());
```
