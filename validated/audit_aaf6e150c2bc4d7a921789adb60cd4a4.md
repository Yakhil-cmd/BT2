### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Block Consensus Reward Distribution via Global `last_reward_block` - (`src/staking/staking.cairo`)

---

### Summary

`IStakingRewardsManager::update_rewards` is specified as callable only by the Starkware sequencer, but the implementation contains **no access control check**. The function updates a **global** `last_reward_block` storage variable regardless of whether `disable_rewards` is `true` or `false`. Any unprivileged caller can invoke `update_rewards(any_active_staker, disable_rewards: true)` at the start of every block, consuming the global per-block slot and preventing the legitimate sequencer from ever distributing consensus rewards to any staker in that block.

---

### Finding Description

In `src/staking/staking.cairo`, `StakingRewardsManagerImpl::update_rewards` (lines 1449–1507) enforces only a pause check via `general_prerequisites()` and a per-block deduplication guard:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks pause
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker validation ...

    // Update last block rewards.  <-- GLOBAL write, not per-staker
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;                    // exits without distributing rewards
    }
    // ... actual reward distribution ...
}
```

Two independent flaws combine:

1. **No caller access control.** The spec at `docs/spec.md:1644–1645` states access is "Only starkware sequencer," but the implementation has no `only_sequencer` or equivalent check. Any address can call this function.

2. **Global `last_reward_block` is written before the `disable_rewards` branch.** Line 1485 writes `self.last_reward_block.write(current_block_number)` unconditionally, even when `disable_rewards = true` causes an early return at line 1487–1488 with zero rewards distributed. The guard at lines 1454–1458 then blocks any further call in the same block with `REWARDS_ALREADY_UPDATED`.

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` at the beginning of every block:
- Passes the deduplication guard (first call in the block)
- Writes `last_reward_block = current_block`
- Returns immediately without distributing any rewards
- Causes every subsequent call in that block (including the sequencer's legitimate call) to revert with `REWARDS_ALREADY_UPDATED`

This can be repeated every block indefinitely.

---

### Impact Explanation

This matches **"Permanent freezing of unclaimed yield"** (High severity).

During the consensus rewards phase (`!is_pre_consensus()`), all staker and delegator yield accrues exclusively through `update_rewards`. If an attacker front-runs the sequencer every block with `disable_rewards: true`, no consensus rewards are ever distributed to any staker or delegator. Stakers' `unclaimed_rewards_own` and pool cumulative reward traces are never updated. The yield is permanently lost for those blocks — it is not deferred, it is simply never credited.

---

### Likelihood Explanation

High. The entry path requires no special role, no stake, and no capital. Any address can call `update_rewards` with an arbitrary active `staker_address` and `disable_rewards: true`. On Starknet, a malicious actor can submit this transaction at the start of every block. The cost is only gas. The attack is fully permissionless and repeatable.

---

### Recommendation

1. **Add sequencer-only access control** to `update_rewards`. The spec already mandates this; the implementation must enforce it:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.roles.only_sequencer();   // add this check
    self.general_prerequisites();
    ...
}
```

2. **Move `last_reward_block.write` after the `disable_rewards` branch**, or make it conditional, so that a no-op call with `disable_rewards = true` does not consume the block's reward slot. Alternatively, use a per-staker last-rewarded-block to eliminate the global contention entirely.

---

### Proof of Concept

```
Block N begins.

1. Attacker (any address) calls:
   update_rewards(staker_address = <any active staker>, disable_rewards = true)

   - general_prerequisites() passes (contract not paused)
   - current_block_number (N) > last_reward_block (N-1) → guard passes
   - staker validation passes
   - last_reward_block.write(N)          ← global slot consumed
   - disable_rewards == true → return    ← no rewards distributed

2. Sequencer calls:
   update_rewards(staker_address = <actual staker>, disable_rewards = false)

   - current_block_number (N) > last_reward_block (N) → FALSE
   - PANIC: REWARDS_ALREADY_UPDATED      ← sequencer blocked

3. Repeat every block → zero consensus rewards ever distributed.
```

The test suite itself demonstrates the missing access control: `staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: true)` is called in unit tests without any `cheat_caller_address_once` role setup, confirming any address can invoke it. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/tests/test.cairo (L3998-4001)
```text
    // `disable_rewards = true`, and self.is_pre_consensus().
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: true);
    let staker_info_after = staking_dispatcher.staker_info_v1(:staker_address);
    assert!(staker_info_after == staker_info_before);
```
