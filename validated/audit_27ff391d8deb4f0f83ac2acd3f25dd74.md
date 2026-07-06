### Title
Missing Caller Restriction on `update_rewards` Allows Anyone to Freeze Staker Yield - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the staking contract is documented to be callable only by the Starkware sequencer, but the implementation contains no on-chain caller check. Any unprivileged address can call it with `disable_rewards: true`, which writes `last_reward_block` to the current block without distributing rewards, permanently blocking the legitimate sequencer from distributing rewards for that block.

### Finding Description
The spec explicitly states the access control for `update_rewards`:

> **access control**: Only starkware sequencer. [1](#0-0) 

However, the implementation in `StakingRewardsManagerImpl` performs no caller identity check whatsoever: [2](#0-1) 

The critical ordering flaw is that `last_reward_block` is written to storage **before** the `disable_rewards` branch is evaluated:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // ← written unconditionally

if disable_rewards || self.is_pre_consensus() {
    return;   // ← exits without distributing rewards
}
``` [3](#0-2) 

The guard that prevents double-calling checks `current_block_number > self.last_reward_block.read()`: [4](#0-3) 

Because `last_reward_block` is a single global slot (not per-staker), once any caller writes it for block N, no further `update_rewards` call can succeed in block N — for **any** staker.

### Impact Explanation
An attacker calls `update_rewards(any_staker_address, disable_rewards: true)` in block N:

1. `last_reward_block` is set to N.
2. The function returns early — zero rewards distributed.
3. The legitimate sequencer's subsequent call in block N reverts with `REWARDS_ALREADY_UPDATED`.
4. Rewards for block N are permanently lost for the targeted staker (and all other stakers, since the slot is global).

If the attacker repeats this every block, stakers accrue **zero** unclaimed yield indefinitely. This matches the allowed impact: **Permanent freezing of unclaimed yield — High**. [5](#0-4) 

### Likelihood Explanation
- No privileged role, no token balance, no prior state required.
- A single transaction per block suffices.
- Starknet gas costs are low, making sustained griefing economically viable.
- The function is publicly exposed via `IStakingRewardsManager`.

Likelihood: **High**.

### Recommendation
Add an explicit caller check at the top of `update_rewards` that asserts `get_caller_address()` equals the configured Starkware sequencer address (stored in contract state), mirroring the pattern used for the attestation contract:

```cairo
fn assert_caller_is_sequencer(self: @ContractState) {
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
}
``` [6](#0-5) 

Alternatively, move `self.last_reward_block.write(current_block_number)` to **after** the `disable_rewards` guard so that a call with `disable_rewards: true` does not consume the block's reward slot.

### Proof of Concept
```
1. Consensus rewards are active (post-consensus epoch).
2. Staker S has staked and is eligible for block rewards.
3. Attacker A (any EOA) calls:
       staking.update_rewards(staker_address: S, disable_rewards: true)
   in block N.
4. last_reward_block is now N; no rewards minted or credited.
5. Sequencer calls:
       staking.update_rewards(staker_address: S, disable_rewards: false)
   in block N → reverts with REWARDS_ALREADY_UPDATED.
6. Staker S receives 0 rewards for block N.
7. Attacker repeats step 3 every block → S accrues 0 yield permanently.
```

The existing test `test_update_rewards_only_staker` confirms the function is callable without any caller restriction — no `cheat_caller_address` is needed: [7](#0-6)

### Citations

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

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

**File:** src/staking/staking.cairo (L2219-2225)
```text
        fn assert_caller_is_attestation_contract(self: @ContractState) {
            assert!(
                get_caller_address() == self.attestation_contract.read(),
                "{}",
                Error::CALLER_IS_NOT_ATTESTATION_CONTRACT,
            );
        }
```

**File:** src/staking/tests/test.cairo (L3488-3527)
```text
fn test_update_rewards_only_staker() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let staking_contract = cfg.test_info.staking_contract;
    let staking_dispatcher = IStakingDispatcher { contract_address: staking_contract };
    let staking_rewards_dispatcher = IStakingRewardsManagerDispatcher {
        contract_address: staking_contract,
    };
    let staking_config_dispatcher = IStakingConfigDispatcher { contract_address: staking_contract };
    let minting_curve_contract = cfg.reward_supplier.minting_curve_contract;
    advance_epoch_global();
    let current_epoch = staking_dispatcher.get_current_epoch();
    cheat_caller_address_once(
        contract_address: staking_contract, caller_address: cfg.test_info.app_governor,
    );
    staking_config_dispatcher.set_consensus_rewards_first_epoch(epoch_id: current_epoch + 2);
    // Advance `K` epochs to start consensus rewards.
    advance_k_epochs_global();
    stake_for_testing_using_dispatcher(:cfg);
    advance_k_epochs_global();
    let staker_address = cfg.test_info.staker_address;
    let staker_info_before = staking_dispatcher.staker_info_v1(:staker_address);
    let (strk_block_rewards, _) = calculate_current_block_rewards_v3(:minting_curve_contract);
    let staker_info_expected = StakerInfoV1 {
        unclaimed_rewards_own: strk_block_rewards, ..staker_info_before,
    };
    let mut spy = snforge_std::spy_events();
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    let staker_info_after = staking_dispatcher.staker_info_v1(:staker_address);
    assert!(staker_info_after == staker_info_expected);
    // Validate StakerRewardsUpdated event.
    let events = spy.get_events().emitted_by(contract_address: staking_contract).events;
    assert_number_of_events(actual: events.len(), expected: 1, message: "update_rewards");
    assert_staker_rewards_updated_event(
        spied_event: events[0],
        :staker_address,
        staker_rewards: strk_block_rewards,
        pool_rewards: [].span(),
    );
}
```
