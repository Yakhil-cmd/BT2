### Title
Missing Caller Authorization on `update_rewards` Allows Anyone to Block Consensus Reward Distribution - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the `Staking` contract is specified to be callable only by the Starknet sequencer, but the implementation contains no such access control check. Any unprivileged caller can invoke it with `disable_rewards: true` every block, permanently preventing consensus rewards from being distributed to stakers and delegators.

### Finding Description
The protocol specification at `docs/spec.md` line 1645 explicitly states:

> **access control**: Only starkware sequencer.

However, the implementation of `StakingRewardsManagerImpl::update_rewards` in `src/staking/staking.cairo` (lines 1447–1507) performs no caller identity check whatsoever. The only guards present are:

1. `general_prerequisites()` — checks the contract is not paused (not a caller check).
2. `current_block_number > self.last_reward_block.read()` — prevents double-calling within the same block.
3. Staker existence and activity checks.

There is no `assert_caller_is_sequencer()`, no role check, and no `get_caller_address()` comparison. The function is exposed via `#[abi(embed_v0)]` on `IStakingRewardsManager`, making it publicly callable by any address.

Critically, `last_reward_block` is written unconditionally at line 1485 **before** the `disable_rewards` branch:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;  // rewards NOT distributed, but last_reward_block IS updated
}
```

This means an attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` consumes the per-block reward slot without distributing any rewards. The sequencer's subsequent call in the same block will revert with `REWARDS_ALREADY_UPDATED`.

### Impact Explanation
An attacker calling `update_rewards(..., disable_rewards: true)` at every block permanently prevents consensus rewards from being credited to `unclaimed_rewards_own` for stakers and from being transferred to delegation pools. Stakers and delegators accumulate zero yield indefinitely. This constitutes **permanent freezing of unclaimed yield**, matching the High impact category.

### Likelihood Explanation
The entry point is fully public — no token, no role, no staked position required. The only precondition is that at least one active staker with non-zero balance exists (trivially true in any live deployment). The attacker pays only gas per block. Likelihood is **High**.

### Recommendation
Add a sequencer-only access control check at the top of `update_rewards`, analogous to the `assert_caller_is_staking_contract` pattern used in the pool contract. For example:

```cairo
fn update_rewards(...) {
    self.general_prerequisites();
    assert!(get_caller_address() == self.sequencer_address.read(), "{}",
        Error::CALLER_IS_NOT_SEQUENCER);
    ...
}
```

Alternatively, restrict the `IStakingRewardsManager` interface so it is not part of the public ABI, or enforce the check via an operator role already present in the roles component.

### Proof of Concept

1. Consensus rewards are active (post `set_consensus_rewards_first_epoch`).
2. Staker `S` is active with non-zero balance.
3. Attacker `A` (any address) calls each new block:
   ```
   IStakingRewardsManager(staking_contract).update_rewards(S, disable_rewards: true)
   ```
4. `last_reward_block` is set to the current block; no rewards are distributed.
5. The sequencer attempts the same call and receives `REWARDS_ALREADY_UPDATED`.
6. Staker `S` and all delegators in `S`'s pools receive zero consensus rewards indefinitely.

The absence of any caller check is confirmed by the test `test_update_rewards_only_staker` (line 3488 of `src/staking/tests/test.cairo`), which calls `update_rewards` with no `cheat_caller_address_once` override — i.e., from an unprivileged default test address — and succeeds without error. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** docs/spec.md (L1626-1652)
```markdown
### update_rewards
```rust
fn update_rewards(ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool);
```
#### description <!-- omit from toc -->
Calculate and update the current block rewards for the for the given `staker_address`.
Send pool rewards to the pools.
Distribute rewards only if `disable_rewards` is False and consensus rewards already started.
#### emits <!-- omit from toc -->
1. [Staker Rewards Updated](#staker-rewards-updated)
2. [Rewards Supplied To Delegation Pool](#rewards-supplied-to-delegation-pool)
#### errors <!-- omit from toc -->
1. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
2. [REWARDS\_ALREADY\_UPDATED](#rewards_already_updated)
3. [STAKER\_NOT\_EXISTS](#staker_not_exists)
4. [INVALID\_STAKER](#invalid_staker)
#### pre-condition <!-- omit from toc -->
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
1. Calculate total block rewards.
2. Calculate staker rewards (include commission) and pool rewards.
3. Update `unclaimed_rewards_own` of the staker.
4. Update and transfer rewards to the pools, if exist.
5. Update Reward Supplier's `unclaimed_rewards`.
6. Update `last_reward_block` to the current block.
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
