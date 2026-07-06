### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Block Consensus Reward Distribution - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the Staking contract is documented in the protocol specification as callable only by the Starkware sequencer, but the implementation enforces no such restriction. Any unprivileged address can call it with `disable_rewards: true`, which advances the global `last_reward_block` checkpoint without distributing any rewards. Because the contract enforces a strict one-call-per-block invariant, a caller who races the sequencer every block can permanently starve all stakers of their consensus-phase yield.

### Finding Description

The specification for `update_rewards` states:

> **access control**: Only starkware sequencer. [1](#0-0) 

The implementation, however, only calls `general_prerequisites()`, which checks that the contract is not paused and that the caller is not the zero address. There is no check that `get_caller_address()` equals the sequencer address. [2](#0-1) 

`general_prerequisites()` is defined as: [3](#0-2) 

The critical ordering flaw is that `last_reward_block` is written **before** the `disable_rewards` guard:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // ← written unconditionally

if disable_rewards || self.is_pre_consensus() {
    return;                                            // ← exits without distributing
}
``` [4](#0-3) 

Any subsequent call in the same block fails with `REWARDS_ALREADY_UPDATED`: [5](#0-4) 

### Impact Explanation

An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` once per block:

1. Advances `last_reward_block` to the current block with zero rewards distributed.
2. Forces every legitimate sequencer call in that block to revert with `REWARDS_ALREADY_UPDATED`.
3. Stakers' `unclaimed_rewards_own` is never incremented; pool rewards are never forwarded to delegation pools.

Sustained over time this constitutes **permanent freezing of unclaimed yield** for all stakers and delegators in the consensus-rewards phase.

**Impact: High** — Permanent freezing of unclaimed yield.

### Likelihood Explanation

- The function is part of the public ABI (`IStakingRewardsManager`) with no caller restriction.
- The attacker needs only a valid staker address (readable from on-chain events) and enough gas to submit one transaction per block.
- No privileged key, bridge access, or external dependency is required.
- The attack is confirmed callable by arbitrary addresses in the test suite itself. [6](#0-5) 

**Likelihood: Medium** — Requires sustained gas expenditure but is fully permissionless.

### Recommendation

Add a sequencer-only guard at the top of `update_rewards`, analogous to the existing pattern used in `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
+   self.assert_caller_is_sequencer(); // enforce spec: "Only starkware sequencer"
    ...
```

Alternatively, move the `self.last_reward_block.write(current_block_number)` call to **after** the `disable_rewards` guard so that a call with `disable_rewards: true` does not consume the block's reward slot.

### Proof of Concept

1. Consensus rewards are active (`!is_pre_consensus()`).
2. Staker `S` has been staked for `K` epochs and has non-zero balance.
3. Attacker `A` (any EOA) submits in every block:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. `last_reward_block` is set to the current block; no rewards are distributed.
5. The sequencer's own `update_rewards(S, false)` call reverts with `REWARDS_ALREADY_UPDATED`.
6. `S.unclaimed_rewards_own` remains zero indefinitely; pool rewards are never forwarded.

The test suite already demonstrates that `update_rewards` is callable by arbitrary addresses without any caller restriction: [7](#0-6)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1447-1489)
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
```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/flow_test/test.cairo (L2817-2830)
```text
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
