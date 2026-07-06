### Title
Unrestricted `update_rewards` with `disable_rewards: true` Allows Any Caller to Permanently Freeze All Staker Yield - (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract has no caller access control and accepts a `disable_rewards: bool` parameter. Any unprivileged address can call `update_rewards(valid_staker_address, true)` every block to consume the global `last_reward_block` slot without distributing any rewards, permanently denying all stakers their consensus-era block rewards.

---

### Finding Description

`update_rewards` is part of `IStakingRewardsManager` and is callable by any non-zero address. The only gate is `general_prerequisites()`, which checks that the contract is not paused and the caller is not the zero address — no check that the caller is the staker, the reward address, or any privileged role. [1](#0-0) 

The function enforces a global, single-slot-per-block invariant via `last_reward_block`: [2](#0-1) 

After passing the block-number check, it unconditionally writes the current block to `last_reward_block`, then branches on `disable_rewards`: [3](#0-2) 

`last_reward_block` is a single global storage slot shared across all stakers: [4](#0-3) 

**Attack path:**

1. In block N, attacker calls `update_rewards(any_valid_staker, disable_rewards: true)`.
2. `last_reward_block` is set to N; the function returns early — no rewards distributed.
3. Any legitimate call to `update_rewards` in block N now reverts with `REWARDS_ALREADY_UPDATED`.
4. Attacker repeats in block N+1, N+2, … indefinitely.

Because only one `update_rewards` call can succeed per block, the attacker's single call per block is sufficient to starve the entire protocol of consensus reward distribution.

---

### Impact Explanation

In the consensus rewards era (after `consensus_rewards_first_epoch` is set), all staker and delegator rewards flow exclusively through `update_rewards`. By consuming the per-block slot with `disable_rewards: true` every block, an attacker permanently freezes all unclaimed yield for every staker and every delegation pool in the protocol. No staker can ever receive block rewards as long as the attack continues.

This maps to **High: Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

The attack requires no special privilege, no capital, and no setup beyond knowing a single valid staker address (publicly readable from the `stakers` vector). The attacker pays only Starknet gas per block. Starknet gas costs are low, making continuous griefing economically viable. The function is fully public and the `disable_rewards` flag is an unguarded boolean parameter.

---

### Recommendation

Restrict who may call `update_rewards` with `disable_rewards: true`. Options:

1. **Require caller to be the staker or their reward address** — consistent with the access pattern used in `claim_rewards` and `increase_stake`.
2. **Remove `disable_rewards` from the public interface** — handle the "no rewards this block" case internally or via a separate privileged function.
3. **Separate the `last_reward_block` update from reward distribution** — only advance the slot when rewards are actually distributed, so a no-op call cannot consume the slot.

---

### Proof of Concept

```
// Attacker script (pseudocode, runs every block)
loop {
    let valid_staker = staking.stakers[0]; // any active staker
    staking.update_rewards(valid_staker, disable_rewards: true);
    // last_reward_block = current_block; no rewards distributed
    // All legitimate update_rewards calls in this block now revert
    wait_for_next_block();
}
```

After this loop runs for any number of blocks, `unclaimed_rewards_own` for every staker remains at its pre-attack value and no delegation pool receives reward updates, permanently freezing all yield accrual.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1448-1460)
```text
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
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```
