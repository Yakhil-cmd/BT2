### Title
Missing Access Control on `update_rewards` Allows Any Caller to Suppress Block Rewards — (File: `src/staking/staking.cairo`)

---

### Summary

`update_rewards` is documented as "Only starkware sequencer" in the spec but the production code enforces no such restriction. Any unprivileged caller can invoke it with `disable_rewards: true`, which writes the global `last_reward_block` and returns without distributing rewards, permanently consuming that block's reward slot for all stakers.

---

### Finding Description

The `general_prerequisites()` guard used by `update_rewards` contains only two checks: [1](#0-0) 

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
```

There is no sequencer-only or role-gated check. The spec explicitly states: [2](#0-1) 

> **access control**: Only starkware sequencer.

Inside `update_rewards`, the global `last_reward_block` is written **before** the `disable_rewards` branch: [3](#0-2) 

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
```

The guard that prevents double-updates is: [4](#0-3) 

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

`last_reward_block` is a **single global storage slot** — not per-staker. One successful call per block, regardless of caller or `staker_address`, exhausts the slot for that block.

---

### Impact Explanation

An attacker calls `update_rewards(any_valid_active_staker, disable_rewards: true)` in block N:

1. `general_prerequisites()` passes (contract not paused, caller non-zero).
2. `current_block_number > last_reward_block` passes (first call this block).
3. `last_reward_block` is written to block N.
4. Function returns early — **zero rewards distributed**.
5. Any subsequent call in block N (including the legitimate sequencer call) reverts with `REWARDS_ALREADY_UPDATED`.

Block N's rewards are permanently lost. Repeated every block, this suppresses all consensus block rewards indefinitely. The impact matches **High: Permanent freezing of unclaimed yield**. [5](#0-4) 

---

### Likelihood Explanation

- Requires no privilege, no stake, no special role — only a non-zero address.
- The only practical mitigation is sequencer-level transaction ordering (sequencer always includes its own call first). However, this is an off-chain operational assumption, not an on-chain enforcement. Any block where the sequencer omits or delays its call is exploitable.
- The attack is cheap (one transaction per block) and can be automated.

---

### Recommendation

Add an explicit caller check inside `update_rewards` (or inside `general_prerequisites` for this path) that restricts the caller to the authorized sequencer address:

```cairo
fn update_rewards(...) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    ...
}
```

Alternatively, gate the function through the existing role/access-control system used elsewhere in the contract.

---

### Proof of Concept

1. Deploy with two active stakers, consensus rewards active.
2. In block N, before the sequencer acts: call `update_rewards(staker_A, disable_rewards: true)` from any EOA.
3. Observe `last_reward_block == N`.
4. Sequencer's call `update_rewards(staker_A, disable_rewards: false)` reverts with `REWARDS_ALREADY_UPDATED`.
5. Advance to block N+1; staker_A's `unclaimed_rewards_own` is unchanged — block N rewards are gone.
6. Repeat for every block; cumulative rewards remain zero while the model predicts non-zero accrual.

The existing test suite already demonstrates that `disable_rewards: true` followed by a second call in the same block produces exactly `REWARDS_ALREADY_UPDATED`: [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L1449-1507)
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

            // Assert staker exists and active.
            // Staker is considered to exist from the moment of `stake` (when `InternalStakerInfo`
            // struct is created) until the calling to `unstake_action` (when `InternalStakerInfo`
            // struct is deleted).
            // Staker remains active until the intent period begins, i.e. K epochs after
            // `unstake_intent` is called.
            let staker_info = self.internal_staker_info(:staker_address);
            let curr_epoch = self.get_current_epoch();
            assert!(
                self.is_staker_active(:staker_address, epoch_id: curr_epoch),
                "{}",
                Error::INVALID_STAKER,
            );

            let staker_pool_info = self.staker_pool_info.entry(staker_address).as_non_mut();
            let (staker_total_strk_balance, staker_total_btc_balance) = self
                .get_staker_total_strk_btc_balance_at_epoch(
                    :staker_address, :staker_pool_info, epoch_id: curr_epoch,
                );
            // Assert staker has non-zero balance.
            // Staker exists with zero balance for the first K epochs after `stake`, then the stake
            // becomes effective.
            assert!(staker_total_strk_balance.is_non_zero(), "{}", Error::INVALID_STAKER);

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

**File:** src/staking/tests/test.cairo (L3887-3894)
```text
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: true);
    // Catch REWARDS_ALREADY_UPDATE - with distribute = false.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
```
