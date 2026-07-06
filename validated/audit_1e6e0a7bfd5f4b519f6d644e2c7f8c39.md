### Title
Permissionless `update_rewards` with `disable_rewards: true` Permanently Freezes All Stakers' Consensus Yield - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in the `Staking` contract is fully permissionless and accepts a `disable_rewards: bool` parameter. When called with `disable_rewards: true`, it updates the global `last_reward_block` storage variable to the current block number but distributes zero rewards. Because `last_reward_block` is a single global slot (not per-staker), any subsequent call to `update_rewards` for the same block — including legitimate calls by actual stakers — reverts with `REWARDS_ALREADY_UPDATED`. An unprivileged attacker can call this every block to permanently freeze all stakers' consensus-era yield.

### Finding Description

`update_rewards` is exposed via `IStakingRewardsManager` with no access control beyond `general_prerequisites()` (which only checks pause state and non-zero caller):

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
    ...
    // Update last block rewards.
    self.last_reward_block.write(current_block_number);   // <-- written unconditionally

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // <-- exits before distributing rewards
    }
    ...
```

`last_reward_block` is a single global `BlockNumber` field in storage, not a per-staker mapping. Writing it before the `disable_rewards` guard means the slot is consumed for the entire block with no rewards emitted.

### Impact Explanation

An attacker calls `update_rewards(any_active_staker, disable_rewards: true)` once per block. Each call:
1. Passes all validation (staker exists, is active, has non-zero balance).
2. Writes `last_reward_block = current_block`.
3. Returns immediately without distributing STRK rewards to any staker or pool.

Every legitimate staker who subsequently calls `update_rewards` in the same block receives `REWARDS_ALREADY_UPDATED`. Because Starknet produces one block per slot, the attacker can repeat this every block, permanently preventing all stakers from accumulating consensus-era yield. The rewards are never credited to `unclaimed_rewards` in the `RewardSupplier`, so they are permanently lost to all stakers and delegators. This matches the **High** impact: permanent freezing of unclaimed yield.

### Likelihood Explanation

The attack requires no stake, no privileged role, and no capital. Any EOA or contract can execute it. The only cost is the gas for one transaction per block. The attacker needs only a single valid (active, non-zero-balance) staker address to pass the precondition checks, which is trivially discoverable from on-chain events.

### Recommendation

1. **Remove `disable_rewards` from the public interface**, or gate it behind a privileged role (e.g., `only_security_agent`).
2. Alternatively, move the `self.last_reward_block.write(current_block_number)` call to **after** the `disable_rewards` guard so that a disabled call does not consume the block slot.
3. Consider making `last_reward_block` a per-staker mapping if the intent is that each staker can claim once per block independently.

### Proof of Concept

```
// Attacker (any address) runs this every block:
staking_contract.update_rewards(
    staker_address: any_active_staker,
    disable_rewards: true,
);
// last_reward_block is now set to current block.
// All legitimate stakers calling update_rewards this block get REWARDS_ALREADY_UPDATED.
// No STRK rewards are distributed to anyone.
// Repeat next block.
```

**Root cause chain:**
- `update_rewards` has no caller restriction [1](#0-0) 
- `last_reward_block` is written unconditionally before the `disable_rewards` guard [2](#0-1) 
- `last_reward_block` is a single global slot, not per-staker [3](#0-2) 
- The guard that skips reward distribution fires after the slot is consumed [4](#0-3) 
- `general_prerequisites` imposes no role check [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1448-1458)
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
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
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
