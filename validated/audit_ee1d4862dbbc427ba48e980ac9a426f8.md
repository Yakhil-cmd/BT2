### Title
Unprivileged Caller Can Permanently Freeze All Staker Block Rewards via `update_rewards` with `disable_rewards: true` - (File: src/staking/staking.cairo)

### Summary

`IStakingRewardsManager::update_rewards` in `src/staking/staking.cairo` has no access control. Any unprivileged caller can invoke it with `disable_rewards: true`, which advances the global `last_reward_block` checkpoint to the current block without distributing any rewards. Because the function enforces a strict "one update per block" invariant on a single global variable, this permanently blocks all legitimate reward updates for that block across every staker.

### Finding Description

`update_rewards` is the consensus-layer entry point for distributing per-block staking rewards. Its implementation in `StakingRewardsManagerImpl` begins with only `general_prerequisites()`, which checks the pause flag and that the caller is non-zero — no role check is performed. [1](#0-0) 

The function then unconditionally writes the current block number to the global `last_reward_block` storage slot before checking `disable_rewards`: [2](#0-1) 

The one-update-per-block guard is enforced against this same global slot: [3](#0-2) 

`last_reward_block` is a single contract-wide variable, not per-staker: [4](#0-3) 

The public interface exposes `disable_rewards` as a plain caller-controlled boolean with no restriction: [5](#0-4) 

### Impact Explanation

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` once per block will:

1. Satisfy the `current_block_number > last_reward_block` guard.
2. Advance `last_reward_block` to the current block.
3. Return immediately without distributing STRK block rewards to any staker or pool.

Every subsequent call to `update_rewards` for the same block — by the legitimate consensus layer or any staker — will revert with `REWARDS_ALREADY_UPDATED`. Because this can be repeated every block at low gas cost, all consensus-era block rewards are permanently frozen for every staker and every delegation pool.

**Impact: High — Permanent freezing of unclaimed yield for all stakers and delegators.**

### Likelihood Explanation

- No special role, token balance, or prior state is required.
- The attacker only needs to be a non-zero address and the contract must be unpaused.
- The attack is repeatable every block at the cost of a single cheap Starknet transaction.
- Front-running the legitimate consensus call is straightforward since the attacker can submit the griefing transaction at the start of any block.

**Likelihood: High.**

### Recommendation

Restrict `update_rewards` to a trusted caller — either the consensus layer address (stored similarly to `attestation_contract`) or a dedicated role. For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_consensus_contract(); // add this guard
    ...
}
```

Alternatively, remove the `disable_rewards` parameter from the public interface entirely and handle the "no-reward" case internally based on on-chain attestation state, so callers cannot influence whether rewards are skipped.

### Proof of Concept

1. Consensus rewards are active (`consensus_rewards_first_epoch` has been set and the current epoch has passed it).
2. A new block `N` is produced.
3. Attacker (any EOA) calls `staking.update_rewards(some_active_staker, disable_rewards: true)`.
   - `current_block_number (N) > last_reward_block` → passes.
   - `last_reward_block` is written to `N`.
   - `disable_rewards == true` → function returns, zero rewards distributed.
4. The legitimate consensus layer (or any staker) calls `staking.update_rewards(staker, disable_rewards: false)` for block `N`.
   - `current_block_number (N) > last_reward_block (N)` → **false** → reverts with `REWARDS_ALREADY_UPDATED`.
5. Block `N`'s rewards are permanently lost for all stakers and pools.
6. Attacker repeats step 3 for every subsequent block, continuously freezing all yield.

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
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
