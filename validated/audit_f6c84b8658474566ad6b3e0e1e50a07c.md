### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Block Reward Distribution - (File: `src/staking/staking.cairo`)

### Summary

`IStakingRewardsManager::update_rewards` in `src/staking/staking.cairo` has no caller restriction. The spec explicitly states access should be "Only starkware sequencer," but the implementation performs no such check. Any unprivileged address can call `update_rewards(staker_address, disable_rewards: true)` to consume the per-block reward slot without distributing any rewards, permanently blocking the legitimate sequencer from distributing rewards for that block.

### Finding Description

`update_rewards` is the consensus-phase reward distribution entry point. It is gated only by a single global block-level guard:

```
current_block_number > self.last_reward_block.read()
```

When the check passes, the function immediately writes `last_reward_block = current_block_number` before any reward logic runs: [1](#0-0) 

If `disable_rewards` is `true`, the function returns immediately after writing `last_reward_block`, distributing nothing: [2](#0-1) 

Because `last_reward_block` is a single global storage slot (not per-staker), any subsequent call in the same block — including the legitimate sequencer's call — reverts with `REWARDS_ALREADY_UPDATED`: [3](#0-2) 

The spec mandates "Only starkware sequencer" for this function: [4](#0-3) 

But the implementation in `StakingRewardsManagerImpl` adds no caller assertion beyond `general_prerequisites()` (which only checks the pause flag): [5](#0-4) 

The interface itself carries no access-control annotation: [6](#0-5) 

### Impact Explanation

An attacker who front-runs the sequencer every block with `update_rewards(any_valid_staker, disable_rewards: true)` will:

1. Consume the one-per-block reward slot for the entire protocol.
2. Prevent `_update_rewards` from ever executing, so `unclaimed_rewards_own` for all stakers never increases.
3. Prevent pool reward transfers, so all delegators' unclaimed yield is also frozen.

This constitutes **permanent freezing of unclaimed yield** for all stakers and delegators — a **High** impact under the allowed scope.

### Likelihood Explanation

The function is publicly callable with no gas-intensive preconditions. A single transaction per block is sufficient. An attacker with any motivation to harm the protocol (e.g., a competing validator, a griefing actor) can sustain this indefinitely at minimal cost. The attack requires no privileged access, no leaked keys, and no external dependencies.

### Recommendation

Add a caller check inside `update_rewards` that restricts execution to the designated sequencer address (stored in contract storage), mirroring the pattern used in `update_rewards_from_attestation_contract`: [7](#0-6) 

Specifically, store a `sequencer_address` (or reuse an existing role) and assert `get_caller_address() == sequencer_address` at the top of `update_rewards`, before the `last_reward_block` write.

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. A new block `N` is produced. The sequencer prepares to call `update_rewards(staker_A, false)`.
3. Attacker front-runs with `update_rewards(staker_A, true)`:
   - `current_block_number (N) > last_reward_block` → passes.
   - `last_reward_block` is written to `N`.
   - `disable_rewards == true` → returns immediately, no rewards distributed.
4. Sequencer's call arrives: `current_block_number (N) > last_reward_block (N)` → **false** → reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeated every block: `unclaimed_rewards_own` for all stakers remains zero indefinitely; pool reward transfers never occur; all staker and delegator yield is permanently frozen.

### Citations

**File:** src/staking/staking.cairo (L1398-1400)
```text
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
```

**File:** src/staking/staking.cairo (L1447-1452)
```text
    #[abi(embed_v0)]
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
```

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

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
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
