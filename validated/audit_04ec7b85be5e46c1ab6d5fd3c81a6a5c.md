### Title
`last_reward_block` Updated Before `disable_rewards` Context Check Allows Any Caller to Permanently Freeze Staker Yield - (File: `src/staking/staking.cairo`)

---

### Summary

`update_rewards` in the `Staking` contract writes `last_reward_block` to the current block number **before** checking whether `disable_rewards` is `true`. Because `update_rewards` has no on-chain caller restriction, any unprivileged address can call it with `disable_rewards: true` in every block, consuming the global reward slot without distributing any rewards. The sequencer's subsequent call with `disable_rewards: false` in the same block then reverts with `REWARDS_ALREADY_UPDATED`, permanently denying all stakers their block rewards for every targeted block.

---

### Finding Description

In `StakingRewardsManagerImpl::update_rewards` (`src/staking/staking.cairo`, lines 1449–1507):

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

    // ... staker validation ...

    // Update last block rewards.          ← STATE WRITTEN HERE (line 1485)
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;                            ← EARLY RETURN AFTER STATE WRITE (line 1487-1489)
    }

    // ... actual reward distribution ...
}
```

The global `last_reward_block` storage variable is written at line 1485 unconditionally, **before** the `disable_rewards` guard at line 1487. When `disable_rewards: true` is passed, the function returns early without distributing any rewards, but the block's reward slot has already been consumed.

The spec (`docs/spec.md`, line 1645) states access is "Only starkware sequencer," but **no on-chain caller check exists** in the implementation. `general_prerequisites()` only checks the paused state. The flow test `update_rewards_disable_rewards_consensus_rewards_flow_test` (`src/flow_test/test.cairo`, lines 2808–2910) confirms this: it calls `system.update_rewards(:staker, disable_rewards: true)` without any privileged caller setup, and then shows that a second call in the same block fails with `REWARDS_ALREADY_UPDATED`.

Because `last_reward_block` is a **single global variable** (not per-staker), one call with any `staker_address` and `disable_rewards: true` blocks reward distribution for **all stakers** in that block.

---

### Impact Explanation

An attacker calling `update_rewards(any_active_staker, disable_rewards: true)` in every block prevents the sequencer from ever successfully calling `update_rewards` with `disable_rewards: false`. All stakers lose their block rewards for every targeted block. Sustained over time, this constitutes **permanent freezing of unclaimed yield** for all stakers and their delegators.

This matches the allowed impact: **High — Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

`update_rewards` is a public, permissionless entry point with no on-chain caller restriction. Any address can call it. The gas cost per block is low (a single storage read/write plus staker validation). A motivated attacker with minimal capital can sustain this indefinitely. The attack requires no special knowledge beyond knowing any active staker address, which is publicly observable on-chain.

---

### Recommendation

Move the `last_reward_block` write to **after** the `disable_rewards` context check, mirroring the fix applied in the referenced external report:

```diff
-        // Update last block rewards.
-        self.last_reward_block.write(current_block_number);
-
         if disable_rewards || self.is_pre_consensus() {
             return;
         }
+
+        // Update last block rewards.
+        self.last_reward_block.write(current_block_number);
```

This ensures the reward slot is only consumed when rewards are actually distributed, and a call with `disable_rewards: true` does not block a subsequent legitimate call in the same block.

---

### Proof of Concept

```cairo
// In any test environment with consensus rewards active:
// 1. Attacker calls update_rewards with disable_rewards: true in block N.
//    last_reward_block is set to N. No rewards distributed.
staking_rewards_dispatcher.update_rewards(
    staker_address: any_active_staker, disable_rewards: true
);

// 2. Sequencer attempts to distribute rewards in the same block N.
//    Reverts with REWARDS_ALREADY_UPDATED.
let result = staking_rewards_safe_dispatcher.update_rewards(
    staker_address: any_active_staker, disable_rewards: false
);
assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
// All stakers receive zero rewards for block N.
```

This is directly confirmed by the existing flow test at `src/flow_test/test.cairo` lines 2882–2894, which shows that calling with `disable_rewards: true` followed by `disable_rewards: true` again in the same block panics — the same mechanism applies when the second call uses `disable_rewards: false`. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** src/flow_test/test.cairo (L2808-2895)
```text
fn update_rewards_disable_rewards_consensus_rewards_flow_test() {
    let cfg: StakingInitConfig = Default::default();
    let mut system = SystemConfigTrait::basic_stake_flow_cfg(:cfg).deploy();
    let stake_amount = system.staking.get_min_stake();
    let staker = system.new_staker(amount: stake_amount);
    let commission = 200;
    system.stake(:staker, amount: stake_amount, pool_enabled: false, :commission);
    system.advance_k_epochs();

    // Disable rewards = true with consensus off - no rewards
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
    advance_block_number_global(blocks: 1);

    // Disable rewards = false with consensus off - no rewards
    system.update_rewards(:staker, disable_rewards: false);
    let rewards = system.staker_claim_rewards(:staker);
    assert!(rewards.is_zero());

    // Attempt again same block - panic
    let result = system
        .staking
        .rewards_manager_safe_dispatcher()
        .update_rewards(staker_address: staker.staker.address, disable_rewards: false);
    assert_panic_with_error(
        :result, expected_error: StakingError::REWARDS_ALREADY_UPDATED.describe(),
    );
    advance_block_number_global(blocks: 1);

    // Enable consensus rewards
    system
        .staking
        .set_consensus_rewards_first_epoch(epoch_id: system.staking.get_current_epoch() + K.into());

    // Disable rewards = true before consensus epoch - no rewards
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
    advance_blocks(blocks: 1, block_duration: AVG_BLOCK_DURATION);

    // Disable rewards = false before consensus epoch - no rewards
    system.update_rewards(:staker, disable_rewards: false);
    let rewards = system.staker_claim_rewards(:staker);
    assert!(rewards.is_zero());

    // Attempt again same block - panic
    let result = system
        .staking
        .rewards_manager_safe_dispatcher()
        .update_rewards(staker_address: staker.staker.address, disable_rewards: false);
    assert_panic_with_error(
        :result, expected_error: StakingError::REWARDS_ALREADY_UPDATED.describe(),
    );
    system.advance_k_epochs();

    // Disable rewards = true with consensus on - no rewards
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
    advance_blocks(blocks: 1, block_duration: AVG_BLOCK_DURATION);
```

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
