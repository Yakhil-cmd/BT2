### Title
Missing Caller Authentication on `update_rewards` Allows Any Address to Permanently Deny Block Rewards — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract is specified to be callable only by the Starkware sequencer, but the implementation contains **no caller authentication check**. Any unprivileged address can call it with `disable_rewards: true`, which advances `last_reward_block` to the current block without distributing rewards. Because the guard `REWARDS_ALREADY_UPDATED` then blocks any subsequent call for that block, the block's rewards are **permanently and irrecoverably lost** for all stakers.

---

### Finding Description

The spec explicitly states:

> **access control**: Only starkware sequencer. [1](#0-0) 

The implementation, however, performs only a pause check (`general_prerequisites()`) and a block-number guard, with **no check on `get_caller_address()`**:

```cairo
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
    // ... no caller identity check ...
    self.last_reward_block.write(current_block_number);   // ← written unconditionally

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← exits before distributing
    }
``` [2](#0-1) 

`last_reward_block` is a **contract-wide** storage variable, not per-staker. Writing it to the current block number before the `disable_rewards` branch means:

1. The attacker's call consumes the block's reward slot.
2. The legitimate sequencer call for the same block reverts with `REWARDS_ALREADY_UPDATED`.
3. No staker receives rewards for that block — ever.

The test suite confirms the absence of any caller restriction: `update_rewards` is invoked in tests with no `cheat_caller_address_once` guard, i.e., from an arbitrary address. [3](#0-2) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker calling `update_rewards(any_staker_address, disable_rewards: true)` once per block permanently denies all stakers their consensus-phase block rewards for that block. Repeated across every block, this constitutes a complete, sustained denial of yield to the entire staker set with no recovery path, because `last_reward_block` cannot be rolled back.

---

### Likelihood Explanation

**High.** The entry point is a public, unauthenticated external function on a deployed L2 contract. No funds, no privileged role, and no special setup are required. The attacker only needs to submit one transaction per block — a trivially automatable on-chain action. The attack is cheap (gas only) and fully griefing: the attacker gains nothing but permanently denies yield to all stakers.

---

### Recommendation

Add a caller check at the top of `update_rewards` that asserts `get_caller_address()` equals the stored sequencer/operator address, mirroring the pattern already used elsewhere in the codebase:

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
```

The `last_reward_block` write must remain **after** the caller check so that a rejected call cannot consume the block's reward slot.

---

### Proof of Concept

1. Consensus rewards are active (post `consensus_rewards_first_epoch`).
2. A new block `N` is produced.
3. Attacker submits: `staking_contract.update_rewards(any_valid_staker, disable_rewards: true)`.
   - `general_prerequisites()` passes (contract not paused).
   - `current_block_number (N) > last_reward_block` passes.
   - `last_reward_block` is written to `N`.
   - Function returns early — zero rewards distributed.
4. Sequencer submits its legitimate `update_rewards(staker, disable_rewards: false)` for block `N`.
   - `current_block_number (N) > last_reward_block (N)` → **false** → reverts with `REWARDS_ALREADY_UPDATED`.
5. Block `N`'s rewards are permanently lost for all stakers.
6. Repeat every block to permanently freeze all yield accrual. [4](#0-3)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1449-1488)
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
```

**File:** src/staking/tests/test.cairo (L3511-3516)
```text
    let staker_info_expected = StakerInfoV1 {
        unclaimed_rewards_own: strk_block_rewards, ..staker_info_before,
    };
    let mut spy = snforge_std::spy_events();
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    let staker_info_after = staking_dispatcher.staker_info_v1(:staker_address);
```
