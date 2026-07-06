### Title
Missing Access Control on `update_rewards` Allows Any Staker to Front-Run the Sequencer and Steal Block Rewards - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in the Staking contract has no caller access control. The protocol specification requires it to be callable only by the Starknet sequencer, but the implementation enforces only a global `last_reward_block` block-level deduplication check. Any registered staker can call `update_rewards` for their own staker address in any block, consuming the single per-block reward slot and preventing the legitimate attesting staker from receiving their earned rewards for that block.

### Finding Description

The `update_rewards` function is the consensus-phase reward distribution entry point. Its only guard against repeated execution is a global `last_reward_block` storage variable:

```rust
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks pause state
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    self.last_reward_block.write(current_block_number);   // global, not per-staker
    ...
}
``` [1](#0-0) 

`last_reward_block` is declared as a single global slot, not a per-staker mapping: [2](#0-1) 

The protocol specification explicitly states the access control requirement:

> **access control**: Only starkware sequencer. [3](#0-2) 

Because `general_prerequisites()` only checks the pause state (it is also used on `stake`, `unstake_intent`, and other user-facing functions), there is no caller restriction on `update_rewards`. The flow tests confirm this: `update_rewards` is called in tests without any `cheat_caller_address` spoofing, meaning any address can invoke it. [4](#0-3) 

The root cause is structurally analogous to the PoolVoter `distributeEx()` bug: a reward distribution function that is callable by an unprivileged actor, with no per-staker or per-epoch idempotency guard, allowing an attacker to consume the reward distribution slot for a block before the legitimate recipient can.

### Impact Explanation

An attacker who is a registered staker with non-zero balance can:

1. Monitor the mempool for the sequencer's `update_rewards` transaction.
2. Front-run it by calling `update_rewards(attacker_staker_address, disable_rewards: false)`.
3. The attacker's staker receives the full block reward proportional to their stake — **without having attested** (i.e., without having earned it under the consensus liveness model).
4. `last_reward_block` is set to the current block number.
5. The sequencer's subsequent call for the legitimate attesting staker reverts with `REWARDS_ALREADY_UPDATED`.
6. The legitimate staker loses their entire block reward for that block.

The attacker can repeat this every block, systematically redirecting block rewards away from attesting stakers to themselves. This constitutes **theft of unclaimed yield** (High severity per the allowed impact scope).

### Likelihood Explanation

- The attacker only needs to be a registered staker (minimum stake), which is an unprivileged role open to anyone.
- Starknet's public mempool makes front-running feasible.
- The attack is repeatable every block with no cooldown.
- No privileged key, bridge compromise, or external dependency is required.

### Recommendation

Add an explicit sequencer-only access control check at the top of `update_rewards`, analogous to how `update_rewards_from_attestation_contract` enforces `assert_caller_is_attestation_contract()`:

```rust
fn update_rewards(...) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer(); // add this
    ...
}
```

The sequencer address should be stored in contract storage and set during initialization, with a governance-controlled update path.

### Proof of Concept

```
1. Attacker registers as a staker with minimum stake (unprivileged, open to anyone).
2. Attacker waits for the consensus rewards phase to be active.
3. In block N, the sequencer prepares to call:
       staking.update_rewards(legitimate_staker, disable_rewards: false)
4. Attacker front-runs with:
       staking.update_rewards(attacker_staker, disable_rewards: false)
   - Attacker's staker receives block N rewards (proportional to their stake).
   - last_reward_block is written to N.
5. Sequencer's call for legitimate_staker reverts:
       Error::REWARDS_ALREADY_UPDATED
6. legitimate_staker.unclaimed_rewards_own is NOT updated for block N.
7. Attacker calls staking.claim_rewards(attacker_staker) to collect stolen yield.
8. Repeat every block.
```

The staking contract's `_update_rewards` internal function, called from `update_rewards`, unconditionally increases `unclaimed_rewards_own` and transfers pool rewards on every successful invocation — there is no idempotency check inside it: [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L186-187)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
```

**File:** src/staking/staking.cairo (L1449-1485)
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
```

**File:** src/staking/staking.cairo (L2348-2365)
```text
            // Update reward supplier.
            let staker_rewards = staker_own_rewards + commission_rewards;
            // Update total rewards.
            reward_supplier_dispatcher
                .update_unclaimed_rewards_from_staking_contract(
                    rewards: staker_rewards + total_pools_rewards,
                );
            // Claim pools rewards.
            claim_from_reward_supplier(
                :reward_supplier_dispatcher,
                amount: total_pools_rewards,
                token_dispatcher: strk_token_dispatcher(),
            );
            // Update staker rewards.
            staker_info.unclaimed_rewards_own += staker_rewards;

            // Update pools rewards.
            let pool_rewards_list = self.update_pool_rewards(:staker_address, :pools_rewards_data);
```

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/flow_test/test.cairo (L2806-2830)
```text
#[test]
#[feature("safe_dispatcher")]
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
```
