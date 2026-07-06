### Title
Anyone Can Call `update_rewards` With `disable_rewards: true`, Permanently Freezing All Staker Block Rewards - (`File: src/staking/staking.cairo`)

---

### Summary

`update_rewards` in the Staking contract is documented as restricted to "Only starkware sequencer" but has **no access control enforcement** in the code. Any unprivileged caller can invoke it with `disable_rewards: true`, which acquires the global `last_reward_block` lock for the current block without distributing any rewards. Because the lock is global and per-block, a bot calling this once per block permanently prevents all stakers from ever receiving block rewards.

---

### Finding Description

The spec at `docs/spec.md` line 1645 states:

> **access control**: Only starkware sequencer.

However, the implementation at `src/staking/staking.cairo` lines 1449–1507 contains no such check:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();   // only checks pause
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker validity checks ...
    self.last_reward_block.write(current_block_number);   // global lock acquired here

    if disable_rewards || self.is_pre_consensus() {
        return;   // exits WITHOUT distributing rewards
    }
    // ... reward distribution ...
}
```

The critical sequence is:

1. `last_reward_block` is a **single global variable** — not per-staker.
2. The guard `current_block_number > self.last_reward_block.read()` prevents any second call in the same block.
3. `last_reward_block` is written **before** the `disable_rewards` early-return check.
4. Therefore, calling `update_rewards(any_valid_staker, disable_rewards: true)` in block N:
   - Sets `last_reward_block = N`
   - Returns immediately without distributing rewards
   - Causes every subsequent call to `update_rewards` in block N to revert with `REWARDS_ALREADY_UPDATED`

An attacker running a bot that calls `update_rewards(any_valid_staker, disable_rewards: true)` once per block permanently prevents the legitimate sequencer from ever distributing block rewards to any staker.

---

### Impact Explanation

All stakers and pool members are permanently denied their block reward accrual. `unclaimed_rewards_own` never increases for any staker, and pool `cumulative_rewards_trace` is never updated. This constitutes **permanent freezing of unclaimed yield** for every participant in the protocol.

This matches the allowed impact: **High — Permanent freezing of unclaimed yield or unclaimed royalties**.

---

### Likelihood Explanation

- `update_rewards` is a public ABI function with no caller restriction in the code.
- Any address can call it with any valid `staker_address` and `disable_rewards: true`.
- The attacker needs only one transaction per block; on Starknet, this is cheap.
- No special privilege, leaked key, or external dependency is required.
- The attack is fully permissionless and can be automated trivially.

---

### Recommendation

Add a caller restriction matching the spec. Either:

1. Assert `get_caller_address() == sequencer_address` (if a sequencer address is stored), or
2. Introduce a dedicated role (e.g., `REWARDS_MANAGER_ROLE`) and assert it at the top of `update_rewards`, before `last_reward_block` is written.

The check must be placed **before** `self.last_reward_block.write(current_block_number)` so that unauthorized callers cannot acquire the global lock.

---

### Proof of Concept

```
Block N:
  Attacker calls: staking.update_rewards(staker=any_valid_staker, disable_rewards=true)
    → last_reward_block = N
    → returns early, no rewards distributed

  Sequencer calls: staking.update_rewards(staker=staker_A, disable_rewards=false)
    → assert!(N > N) → PANICS with REWARDS_ALREADY_UPDATED

Block N+1:
  Attacker calls again: staking.update_rewards(staker=any_valid_staker, disable_rewards=true)
    → last_reward_block = N+1
    → returns early, no rewards distributed

  Sequencer call again → PANICS with REWARDS_ALREADY_UPDATED

... repeated every block → all stakers permanently receive zero block rewards
```

**Root cause location:** [1](#0-0) 

**Spec access control requirement (violated):** [2](#0-1) 

**Global lock written before early-return:** [3](#0-2)

### Citations

**File:** src/staking/staking.cairo (L1449-1489)
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
```

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
