### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Consume a Block's Reward Slot Without Distributing Rewards - (File: src/staking/staking.cairo)

### Summary

`update_rewards` in `staking.cairo` writes `last_reward_block` to the current block number **before** checking the `disable_rewards` flag. Because there is no caller restriction enforced in code (despite the spec stating "Only starkware sequencer"), any unprivileged address can call `update_rewards(staker_address, disable_rewards=true)`, advance the global `last_reward_block` marker, and permanently prevent reward distribution for that block.

### Finding Description

`update_rewards` is the consensus-phase reward distribution entry point. Its implementation is:

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

    // Update last block rewards.          ← marker written HERE
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;                            ← exits WITHOUT distributing rewards
    }
    // ... actual reward distribution ...
}
``` [1](#0-0) 

`general_prerequisites()` only checks whether the contract is paused; it does **not** restrict the caller to the Starkware sequencer. [2](#0-1) 

`last_reward_block` is a single **global** storage variable. Once it is written to `current_block_number`, the guard at line 1454–1458 causes every subsequent call in the same block to revert with `REWARDS_ALREADY_UPDATED`. [3](#0-2) 

The spec explicitly states the intended access control is "Only starkware sequencer", but this is not enforced in code. [4](#0-3) 

### Impact Explanation

Each block in the consensus-rewards phase carries a fixed reward amount derived from `avg_block_duration` and the yearly mint. Rewards are not accumulated across blocks; a block whose `update_rewards` call distributes nothing simply loses those rewards forever. An attacker who front-runs the sequencer with `disable_rewards=true` causes the staker (and all delegators in the staker's pools) to permanently forfeit one block's worth of STRK rewards. Because `last_reward_block` is global, a single griefing call affects **all** stakers for that block.

This matches the allowed impact: **Permanent freezing of unclaimed yield**.

### Likelihood Explanation

The function is publicly callable with no on-chain sequencer check. The attacker needs only to submit a transaction in the same block as the sequencer's intended `update_rewards` call. On Starknet, where transaction ordering within a block is controlled by the sequencer, a malicious sequencer could trivially self-grief; an external attacker can attempt to race the sequencer. The cost is only gas.

### Recommendation

Add an explicit sequencer-only guard, analogous to the pattern used for `update_rewards_from_attestation_contract` (which checks `caller == attestation_contract`):

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
    ...
    self.last_reward_block.write(current_block_number);
    if disable_rewards || self.is_pre_consensus() {
        return;
    }
    ...
}
```

Alternatively, move `self.last_reward_block.write(current_block_number)` to **after** the `disable_rewards` branch so that a no-op call does not consume the block's reward slot — mirroring the fix pattern from the external report (accumulate state before updating the marker).

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. Attacker calls `update_rewards(any_valid_staker, disable_rewards: true)` in block N.
3. `last_reward_block` is written to N; function returns early — zero rewards distributed.
4. Sequencer attempts `update_rewards(staker, disable_rewards: false)` in the same block N.
5. The assert `current_block_number > self.last_reward_block.read()` fails → `REWARDS_ALREADY_UPDATED`.
6. Block N's rewards are permanently lost for all stakers and delegators.

The test `test_update_rewards_without_distribute` (line 3985) already demonstrates that calling with `disable_rewards=true` leaves `staker_info` unchanged while advancing `last_reward_block`, confirming the marker is consumed without reward distribution. [5](#0-4)

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

**File:** docs/spec.md (L1644-1646)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```

**File:** src/staking/tests/test.cairo (L3985-4001)
```text
fn test_update_rewards_without_distribute() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let staking_contract = cfg.test_info.staking_contract;
    let staking_dispatcher = IStakingDispatcher { contract_address: staking_contract };
    let staking_rewards_dispatcher = IStakingRewardsManagerDispatcher {
        contract_address: staking_contract,
    };
    let staking_config_dispatcher = IStakingConfigDispatcher { contract_address: staking_contract };
    stake_for_testing_using_dispatcher(:cfg);
    advance_k_epochs_global();
    let staker_address = cfg.test_info.staker_address;
    let staker_info_before = staking_dispatcher.staker_info_v1(:staker_address);
    // `disable_rewards = true`, and self.is_pre_consensus().
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: true);
    let staker_info_after = staking_dispatcher.staker_info_v1(:staker_address);
    assert!(staker_info_after == staker_info_before);
```
