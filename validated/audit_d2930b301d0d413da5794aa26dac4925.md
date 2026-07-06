### Title
`update_rewards` Updates `last_reward_block` Without Distributing Rewards, Enabling Griefing Freeze of Yield — (File: `src/staking/staking.cairo`)

### Summary

`StakingRewardsManagerImpl::update_rewards` is callable by any non-zero address. It unconditionally writes `last_reward_block` to the current block number **before** checking the `disable_rewards` flag. When an unprivileged caller passes `disable_rewards: true`, the block is permanently "consumed" in the accounting state with no rewards distributed, and the legitimate consensus mechanism cannot call the function again for the same block.

### Finding Description

`update_rewards` is the entry point through which the consensus mechanism distributes per-block staking rewards. Its access control is limited to `general_prerequisites()`, which only asserts the contract is not paused and the caller is non-zero. [1](#0-0) 

The function writes `last_reward_block` at line 1485 **before** the early-return guard at line 1487: [2](#0-1) 

The guard at line 1453 enforces that `current_block_number > last_reward_block`: [3](#0-2) 

Because `last_reward_block` is a **global** (not per-staker) storage variable, once it is set to block N by any caller, no other call can succeed in block N. When `disable_rewards: true` is passed, the block is marked consumed but `staker_info.unclaimed_rewards_own` is never incremented: [4](#0-3) 

This is the direct accounting analog to M-08: a state variable (`last_reward_block`) is updated to reflect that a block was "processed," but the corresponding balance variable (`unclaimed_rewards_own`) is never updated, leaving it permanently stale for that block.

### Impact Explanation

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` in every block:

1. Marks each block as processed (`last_reward_block = current_block`).
2. Causes the legitimate consensus call to revert with `REWARDS_ALREADY_UPDATED`.
3. Ensures `unclaimed_rewards_own` is never incremented for any staker.

This constitutes **permanent freezing of unclaimed yield** for all stakers in the protocol, matching the High-severity impact category.

### Likelihood Explanation

- No privileged role is required; any non-zero EOA or contract can call `update_rewards`.
- The only cost to the attacker is gas per block, which is low on Starknet L2.
- The attacker needs no capital, no special knowledge, and gains nothing — pure griefing.
- The attack is fully automated and can run indefinitely.

### Recommendation

1. **Restrict `update_rewards` to the consensus/attestation contract** (or a designated operator role), analogous to how `update_rewards_from_attestation_contract` is restricted via `assert_caller_is_attestation_contract`.
2. **Move the `last_reward_block` write after the `disable_rewards` check**, so that a no-op call does not consume the block slot:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
// Only mark the block as processed when rewards are actually distributed.
self.last_reward_block.write(current_block_number);
// ... reward calculation and distribution ...
```

### Proof of Concept

```
Block N:
  Attacker calls: staking.update_rewards(staker=any_active_staker, disable_rewards=true)
    → general_prerequisites() passes (not paused, caller != 0)
    → assert!(N > last_reward_block) passes
    → staker checks pass
    → last_reward_block.write(N)          ← block consumed
    → disable_rewards == true → return    ← no rewards distributed

  Consensus mechanism calls: staking.update_rewards(staker=selected_staker, disable_rewards=false)
    → assert!(N > last_reward_block) FAILS (N > N is false)
    → reverts with REWARDS_ALREADY_UPDATED

Block N+1: attacker repeats → selected staker again receives nothing.

After K blocks: unclaimed_rewards_own for all stakers remains 0.
```

### Citations

**File:** src/staking/staking.cairo (L1449-1458)
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
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

**File:** src/staking/staking.cairo (L2362-2362)
```text
            staker_info.unclaimed_rewards_own += staker_rewards;
```
