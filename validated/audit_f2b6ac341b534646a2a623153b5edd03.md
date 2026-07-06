### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Suppress Block Rewards - (File: `src/staking/staking.cairo`)

---

### Summary

`IStakingRewardsManager::update_rewards` is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can call it with `disable_rewards: true`, consuming the single per-block reward slot and permanently preventing the legitimate sequencer from distributing rewards for that block.

---

### Finding Description

The protocol spec explicitly restricts `update_rewards` to the Starkware sequencer:

> **access control**: Only starkware sequencer. [1](#0-0) 

The implementation in `StakingRewardsManagerImpl` enforces no such restriction. The only gate is `general_prerequisites()` (a pause check) and a per-block deduplication guard:

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
    self.last_reward_block.write(current_block_number);  // slot consumed here
    if disable_rewards || self.is_pre_consensus() {
        return;  // exits without distributing rewards
    }
``` [2](#0-1) 

The critical sequence is:

1. `last_reward_block` is written to `current_block_number` at line 1485 **unconditionally**, before the `disable_rewards` branch.
2. If `disable_rewards == true`, the function returns immediately without computing or distributing any rewards.
3. Any subsequent call in the same block (including the legitimate sequencer's call) hits `REWARDS_ALREADY_UPDATED` and reverts.

There is no `assert_caller_is_sequencer`, no role check, and no allowlist anywhere in the function or in `general_prerequisites`. [3](#0-2) 

The interface definition confirms the function is fully public with no documented restriction: [4](#0-3) 

---

### Impact Explanation

**Permanent freezing of unclaimed yield.**

Block rewards in the consensus phase are computed and credited once per block. Because `last_reward_block` is set to the current block number before the `disable_rewards` early-return, the reward slot for that block is permanently consumed with zero distribution. There is no mechanism to retroactively credit missed blocks. An attacker who front-runs the sequencer every block can suppress 100% of consensus-phase staker and delegator rewards indefinitely.

---

### Likelihood Explanation

The function is callable by any externally-owned address with no preconditions beyond the contract being unpaused and the staker being valid. The attacker only needs to:

1. Know any active staker address (trivially available from on-chain `NewStaker` events).
2. Submit a transaction in each block before the sequencer's `update_rewards` transaction.

On Starknet, transaction ordering within a block is sequencer-controlled, but the sequencer itself is the intended caller — a griefing actor can simply submit the call as a regular user transaction. The cost is only gas per block.

---

### Recommendation

Add a caller check at the top of `update_rewards` that asserts `get_caller_address()` equals the registered Starkware sequencer address (stored in contract storage or via a role). This mirrors the pattern already used for `update_rewards_from_attestation_contract`, which correctly asserts `CALLER_IS_NOT_ATTESTATION_CONTRACT`: [5](#0-4) 

---

### Proof of Concept

```
// Attacker is any unprivileged address.
// Precondition: consensus rewards are active, staker_address is a valid active staker.

// Step 1: Attacker calls update_rewards with disable_rewards=true in block N.
//         No access control prevents this.
staking_rewards_dispatcher.update_rewards(
    staker_address: any_valid_staker,
    disable_rewards: true,   // no rewards distributed
);
// last_reward_block is now set to block N.

// Step 2: Sequencer attempts its legitimate call in the same block N.
// Reverts with REWARDS_ALREADY_UPDATED.
staking_rewards_dispatcher.update_rewards(
    staker_address: any_valid_staker,
    disable_rewards: false,
);
// => panic: REWARDS_ALREADY_UPDATED

// Repeating this every block permanently freezes all consensus-phase yield.
```

The existing test suite already demonstrates the `REWARDS_ALREADY_UPDATED` revert behavior when called twice in the same block, confirming the slot-consumption mechanic: [6](#0-5)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
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

**File:** src/staking/interface.cairo (L303-311)
```text
#[starknet::interface]
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```

**File:** src/staking/tests/test.cairo (L3878-3884)
```text
    // Catch REWARDS_ALREADY_UPDATED.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
```
