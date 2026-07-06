### Title
Missing Access Control on `update_rewards` Allows Any Caller to Consume Block Reward Slots Without Distributing Rewards - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in `StakingRewardsManagerImpl` unconditionally writes `last_reward_block` to the current block number before checking whether rewards should actually be distributed. Because no caller access control is enforced (the spec says "Only starkware sequencer" but the code does not assert this), any unprivileged address can call `update_rewards(staker_address, disable_rewards: true)` to permanently consume a block's reward slot without distributing any rewards to stakers or delegators.

### Finding Description

The spec at `docs/spec.md:1644-1645` states:

> **access control**: Only starkware sequencer.

However, the implementation at `src/staking/staking.cairo:1449-1507` contains no such check. The function only calls `self.general_prerequisites()` (a pause check) and then proceeds:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // ← always written

if disable_rewards || self.is_pre_consensus() {
    return;                                            // ← no rewards distributed
}
``` [1](#0-0) 

`last_reward_block` is written **before** the early-return guard. Once it is written, any subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [2](#0-1) 

The interface definition confirms the function is publicly exposed with no caller restriction in the ABI: [3](#0-2) 

### Impact Explanation

An attacker calls `update_rewards(any_active_staker_address, disable_rewards: true)` once per block. This:

1. Sets `last_reward_block` to the current block number.
2. Returns immediately — zero rewards are credited to `unclaimed_rewards_own` or any pool.
3. Blocks the legitimate sequencer call for the same block with `REWARDS_ALREADY_UPDATED`.

Every griefed block permanently erases that block's consensus rewards for the targeted staker and all of its delegation pool members. Rewards are never retroactively recovered because the per-block accounting is final once `last_reward_block` advances.

This matches the **High** impact category: **Permanent freezing of unclaimed yield**.

### Likelihood Explanation

- No special role, token balance, or privileged key is required.
- Any EOA or contract can call `update_rewards` with `disable_rewards: true`.
- The attacker only needs to submit a transaction before the sequencer's own reward-distribution transaction in each block.
- The cost is a single cheap transaction per block; the attacker has no profit motive but causes direct, irreversible yield loss to stakers and delegators.

### Recommendation

Add a caller check at the top of `update_rewards` that asserts the caller is the authorized sequencer address (stored in contract storage or a role), consistent with the spec's stated access control. Alternatively, move `self.last_reward_block.write(current_block_number)` to **after** the `disable_rewards || is_pre_consensus()` guard so that the slot is only consumed when rewards are actually distributed.

### Proof of Concept

1. Deploy the system and advance past the consensus rewards activation epoch so `is_pre_consensus()` returns `false`.
2. From any arbitrary address (no special role), call:
   ```
   staking.update_rewards(staker_address, disable_rewards: true)
   ```
3. Observe that `last_reward_block` is now set to the current block and `staker_info.unclaimed_rewards_own` is unchanged.
4. The sequencer's intended call `update_rewards(staker_address, disable_rewards: false)` in the same block now reverts with `REWARDS_ALREADY_UPDATED`.
5. Advance one block and repeat — the staker accumulates zero rewards indefinitely.

The existing test `test_update_rewards_without_distribute` at `src/staking/tests/test.cairo:3984` already demonstrates that calling with `disable_rewards: true` updates `last_reward_block` without distributing rewards, and that a subsequent call in the same block fails — confirming the griefing path is reachable without any caller restriction. [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L1453-1458)
```text
            let current_block_number = starknet::get_block_number();
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
                Error::REWARDS_ALREADY_UPDATED,
            );
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
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

**File:** src/staking/tests/test.cairo (L3984-4001)
```text
#[test]
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
