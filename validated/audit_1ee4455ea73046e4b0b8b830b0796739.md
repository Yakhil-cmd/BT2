### Title
Unprivileged Caller Can Permanently Freeze Consensus Block Rewards via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

### Summary
Any unprivileged address can call `update_rewards` with `disable_rewards: true`, which advances the global `last_reward_block` sentinel without distributing any rewards. Because the contract enforces exactly one reward update per block, a griever who front-runs every block permanently prevents all stakers from accumulating consensus-era yield.

### Finding Description
`update_rewards` is part of `IStakingRewardsManager` and carries no caller-identity restriction beyond `general_prerequisites()`, which only checks the pause flag and a non-zero caller. [1](#0-0) 

The very first state-mutating action inside the function is writing the current block number to `last_reward_block`: [2](#0-1) 

This write happens **unconditionally**, before the `disable_rewards` branch: [3](#0-2) 

When `disable_rewards` is `true` the function returns immediately after updating `last_reward_block`, skipping `_update_rewards` entirely. Any subsequent legitimate call in the same block is rejected: [4](#0-3) 

`last_reward_block` is a single global field shared across all stakers: [5](#0-4) 

### Impact Explanation
Consensus-era block rewards are the sole yield source for stakers once `consensus_rewards_first_epoch` is active. If an attacker calls `update_rewards(<any_valid_staker>, disable_rewards: true)` at the first transaction of every block, `last_reward_block` is consumed for that block with zero rewards minted. No staker can receive block rewards for any block the attacker front-runs. Sustained over time this constitutes **permanent freezing of unclaimed yield** for all stakers and delegators — a High-severity impact under the allowed scope.

### Likelihood Explanation
The call requires no special role, no stake, and no prior relationship with any staker. The attacker only needs to supply a valid (existing, active) `staker_address` and pass `disable_rewards: true`. On Starknet, transaction fees are low enough that blocking every block is economically feasible for a motivated adversary. The attack is also composable: a single multicall per block suffices.

### Recommendation
Restrict who may supply `disable_rewards: true`. The simplest fix is to require the caller to be the staker themselves (or a designated keeper role) before honouring `disable_rewards: true`, or to remove the parameter from the public interface entirely and handle the "no-op" case through a separate privileged function. At minimum, the `last_reward_block` write should be moved to **after** the `disable_rewards` guard so that a disabled call does not consume the block's reward slot.

### Proof of Concept
1. Consensus rewards are active (`get_current_epoch() >= consensus_rewards_first_epoch`).
2. At the start of block `N`, attacker calls:
   ```
   staking.update_rewards(staker_address=<any_active_staker>, disable_rewards=true)
   ```
3. `last_reward_block` is written to `N`; the function returns without calling `_update_rewards`.
4. Any legitimate call to `update_rewards` for block `N` reverts with `REWARDS_ALREADY_UPDATED`.
5. Stakers accumulate zero rewards for block `N`.
6. Attacker repeats at block `N+1`, `N+2`, … — all stakers are permanently frozen out of consensus yield.

### Citations

**File:** src/staking/staking.cairo (L187-187)
```text
        last_reward_block: BlockNumber,
```

**File:** src/staking/staking.cairo (L1449-1452)
```text
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

**File:** src/staking/staking.cairo (L1484-1485)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);
```

**File:** src/staking/staking.cairo (L1487-1489)
```text
            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```
