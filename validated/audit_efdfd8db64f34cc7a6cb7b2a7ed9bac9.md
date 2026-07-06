The key question is whether `update_rewards` has the caller restriction the spec mandates. Let me trace the exact code path.

**Spec says** (docs/spec.md line 1645): access control is "Only starkware sequencer."

**Implementation** (`src/staking/staking.cairo` lines 1449–1507):

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();   // only checks is_paused
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}", Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker existence checks ...
    self.last_reward_block.write(current_block_number);   // global, per-block gate
    if disable_rewards || self.is_pre_consensus() {
        return;   // no rewards distributed, but block slot consumed
    }
    // ... distribute rewards ...
}
```

There is **no caller check** — `general_prerequisites()` only asserts the contract is not paused. Any address can call this function.

---

### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Suppress Block Rewards — (`src/staking/staking.cairo`)

### Summary
`update_rewards` is documented as restricted to "Only starkware sequencer" but the implementation performs no caller validation. Any unprivileged address can call it with `disable_rewards: true`, consuming the global `last_reward_block` slot for the current block without distributing any rewards, permanently discarding that block's yield for the targeted staker.

### Finding Description

The `StakingRewardsManagerImpl::update_rewards` function at [1](#0-0)  calls only `self.general_prerequisites()`, which checks the pause flag but performs no caller identity check.

The spec explicitly states the access control should be "Only starkware sequencer": [2](#0-1) 

The global `last_reward_block` is written unconditionally before the `disable_rewards` branch: [3](#0-2) 

Once `last_reward_block` equals the current block number, any subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`. The block's reward opportunity is permanently gone.

The interface definition confirms the function is public with no restriction: [4](#0-3) 

### Impact Explanation

An attacker calls `update_rewards(victim_staker, disable_rewards: true)` on every block. Each call:
1. Passes the `REWARDS_ALREADY_UPDATED` guard (new block).
2. Writes `last_reward_block = current_block`.
3. Returns immediately due to `disable_rewards == true` — zero rewards distributed.

The victim staker's `unclaimed_rewards_own` is never incremented. The block reward is permanently lost. Repeated across all blocks, this constitutes **permanent freezing of unclaimed yield** for any targeted active staker.

### Likelihood Explanation

The function is publicly callable on-chain with no gas-economic barrier beyond transaction fees. An attacker only needs to front-run the legitimate sequencer call each block, which is straightforward on Starknet where transaction ordering within a block is observable.

### Recommendation

Enforce the access control stated in the spec. Add a sequencer-only guard at the top of `update_rewards`, analogous to how `update_rewards_from_attestation_contract` checks `CALLER_IS_NOT_ATTESTATION_CONTRACT`: [5](#0-4) 

### Proof of Concept

1. Deploy with two active stakers, consensus rewards active.
2. On each new block, attacker calls `update_rewards(staker_A, disable_rewards: true)` before the sequencer.
3. Sequencer's subsequent call reverts with `REWARDS_ALREADY_UPDATED`.
4. After N blocks, `staker_A.unclaimed_rewards_own == 0` while the model predicts `N * block_reward`.
5. The existing test `update_rewards_disable_rewards_consensus_rewards_flow_test` already demonstrates that `disable_rewards: true` with consensus active yields zero rewards and sets the block gate: [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L1449-1452)
```text
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
```

**File:** src/staking/staking.cairo (L1484-1488)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
```

**File:** docs/spec.md (L1153-1158)
```markdown
3. [CALLER\_IS\_NOT\_ATTESTAION\_CONTRACT](#caller_is_not_attestation_contract)
4. [STAKER\_NOT\_EXISTS](#staker_not_exists)
5. [UNSTAKE\_IN\_PROGRESS](#unstake_in_progress)
#### pre-condition <!-- omit from toc -->
#### access control <!-- omit from toc -->
Only attestation contract.
```

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/interface.cairo (L304-311)
```text
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
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
