The critical finding is in `general_prerequisites`: [1](#0-0) 

```rust
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
```

The spec says `update_rewards` is "Only starkware sequencer" access-controlled, but the actual code enforces **no such check** — only "not paused" and "caller != zero address". [2](#0-1) 

The `last_reward_block` is a **global** (not per-staker) storage slot: [3](#0-2) 

---

### Title
Missing Caller Authorization in `update_rewards` Allows Any Address to Permanently Suppress Block Rewards — (`src/staking/staking.cairo::update_rewards`)

### Summary
`update_rewards` is documented as restricted to the Starkware sequencer, but the implementation enforces no such check. Any unprivileged address can call it with `disable_rewards: true`, consuming the global `last_reward_block` slot for the current block and permanently discarding that block's rewards for all stakers.

### Finding Description
The `update_rewards` entry point at line 1449 calls only `general_prerequisites()`, which checks `assert_is_unpaused()` and `assert_caller_is_not_zero()`. [4](#0-3) 

After passing those checks, the function writes `last_reward_block = current_block_number` unconditionally before evaluating `disable_rewards`: [5](#0-4) 

Because `last_reward_block` is a single global value (not per-staker), once it is written for block N, every subsequent call to `update_rewards` in block N reverts with `REWARDS_ALREADY_UPDATED`. If the attacker calls first with `disable_rewards: true`, the early return fires and zero rewards are distributed. The legitimate sequencer call later in the same block is permanently blocked.

The spec explicitly states the intended access control: [6](#0-5) 

### Impact Explanation
For every block where the attacker front-runs the sequencer, all stakers lose that block's STRK rewards permanently — there is no catch-up mechanism. The attacker can do this continuously at negligible cost (only gas), causing **permanent freezing of unclaimed yield** for the entire validator set.

### Likelihood Explanation
On Starknet, transaction ordering within a block is controlled by the sequencer, but the function is callable by any EOA or contract. A determined attacker submitting transactions at the start of each block can reliably win the race. The cost is only gas; there is no economic barrier.

### Recommendation
Add an explicit caller check restricting `update_rewards` to the authorized sequencer address, consistent with the spec. For example:

```rust
fn update_rewards(...) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    ...
}
```

### Proof of Concept
1. Deploy the staking contract with two active stakers past the K-epoch warmup period and with consensus rewards active.
2. At the start of block N, call `update_rewards(any_valid_staker, disable_rewards: true)` from an arbitrary address.
3. Observe: `last_reward_block` is set to N, no rewards are distributed.
4. The legitimate sequencer call to `update_rewards` in block N reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeat for every block. Both stakers accumulate zero rewards indefinitely.

This is directly confirmed by the existing test `update_rewards_disable_rewards_consensus_rewards_flow_test`, which shows that calling with `disable_rewards: true` distributes zero rewards and that a second call in the same block reverts — the test just never checks that the caller is privileged. [7](#0-6)

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

**File:** src/staking/staking.cairo (L1794-1797)
```text
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** docs/spec.md (L1644-1646)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```

**File:** src/flow_test/test.cairo (L2882-2895)
```text
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
