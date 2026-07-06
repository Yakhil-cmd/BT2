### Title
Unrestricted `update_rewards` Allows Any Caller to Permanently Freeze Staker Yield - (File: src/staking/staking.cairo)

### Summary

`IStakingRewardsManager::update_rewards` in `staking.cairo` is callable by any address. The protocol specification explicitly states its access control is "Only starkware sequencer," but no caller check is implemented. An unprivileged attacker can call `update_rewards(valid_staker, disable_rewards: true)` every block, consuming the global `last_reward_block` slot without distributing rewards, permanently denying yield to all stakers.

### Finding Description

The `update_rewards` function is the sole mechanism by which per-block consensus rewards are calculated and credited to stakers and their delegation pools. The spec at `docs/spec.md` line 1644–1645 states:

> **access control**: Only starkware sequencer.

However, the implementation at `src/staking/staking.cairo` lines 1449–1488 contains no `get_caller_address()` check whatsoever:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();          // only checks pause state
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... no caller identity check ...
    self.last_reward_block.write(current_block_number);   // global slot consumed
    if disable_rewards || self.is_pre_consensus() {
        return;                            // exits without distributing rewards
    }
    // distribute rewards ...
```

`last_reward_block` is a single global storage variable (no per-staker key). Once it is written for block N, any subsequent call at block N reverts with `REWARDS_ALREADY_UPDATED`. The `disable_rewards: true` path writes `last_reward_block` and returns immediately, distributing nothing.

### Impact Explanation

An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` at block N:

1. Writes `last_reward_block = N` with zero reward distribution.
2. The legitimate sequencer call at block N reverts with `REWARDS_ALREADY_UPDATED`.
3. Rewards for block N are permanently lost — the contract's missed-block compensation (`strk_block_rewards * missed_blocks`) only covers blocks between the *last successful* `update_rewards` call and the current block; block N is now counted as "already processed."

Repeated every block, this permanently freezes all unclaimed yield for every staker and delegation pool in the protocol. This matches the allowed impact: **Permanent freezing of unclaimed yield**.

### Likelihood Explanation

- The function is publicly callable with no authentication barrier.
- The only precondition is that a valid, active staker address with non-zero balance exists — trivially satisfied on a live network.
- The gas cost of the attack is low (a single contract call per block).
- No profit motive is required; the attack is pure griefing.

### Recommendation

Add a caller check at the top of `update_rewards`, analogous to the checks already present on other privileged functions in the same contract (e.g., `assert_caller_is_attestation_contract`):

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.assert_caller_is_sequencer();   // add this
    self.general_prerequisites();
    // ...
```

Alternatively, restrict the function to the attestation contract or a dedicated sequencer role stored in contract state, consistent with the existing role-based access control pattern used throughout the codebase.

### Proof of Concept

1. Deploy the staking system and advance K epochs so a staker has non-zero balance.
2. At block N (before the sequencer acts), any address calls:
   ```
   IStakingRewardsManagerDispatcher { contract_address: staking_contract }
       .update_rewards(staker_address: any_valid_staker, disable_rewards: true);
   ```
3. `last_reward_block` is now N; no rewards are distributed.
4. The sequencer's call at block N reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeat every block — all staker and pool rewards are permanently frozen.

This is confirmed by the existing test `test_update_rewards_assertions_already_consensus` (lines 3956–3963 of `src/staking/tests/test.cairo`), which demonstrates that a single call to `update_rewards` at a given block prevents any further call at that block — the test calls it from an unprivileged address with no special setup. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** src/staking/tests/test.cairo (L3956-3963)
```text
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    // Catch REWARDS_ALREADY_UPDATED.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
```
