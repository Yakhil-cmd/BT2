### Title
Unprivileged Caller Can Permanently Freeze Consensus Reward Accumulation via `update_rewards` with `disable_rewards: true` - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in `IStakingRewardsManager` is publicly callable with no access control. It accepts a caller-controlled `disable_rewards: bool` parameter. Because the global `last_reward_block` is written **before** the `disable_rewards` guard, any unprivileged address can call `update_rewards(valid_staker, disable_rewards: true)` once per block to consume the per-block reward slot without distributing any rewards, permanently blocking all stakers from accumulating consensus-era yield.

### Finding Description
`update_rewards` is exposed as a public ABI entry point with no role check: [1](#0-0) 

The only gate is `general_prerequisites()`, which only asserts the contract is unpaused and the caller is non-zero: [2](#0-1) 

Inside the function, `last_reward_block` is written to storage **unconditionally**, before the `disable_rewards` branch: [3](#0-2) 

The `disable_rewards` check that skips actual reward distribution comes only after: [4](#0-3) 

Because `last_reward_block` is a single global value shared across all stakers, consuming it with `disable_rewards: true` blocks every other staker from calling `update_rewards` in the same block (the `current_block_number > last_reward_block` assertion fails for all subsequent callers in that block): [5](#0-4) 

### Impact Explanation
An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` once per block:
- Consumes the global per-block reward slot for that block.
- Prevents every staker in the protocol from receiving consensus block rewards for that block.
- If sustained across blocks, permanently freezes the accumulation of unclaimed yield for all stakers and their delegators.

This matches **High: Permanent freezing of unclaimed yield** from the allowed impact scope.

### Likelihood Explanation
The attack requires only:
1. Knowledge of any active staker address with non-zero balance (all staker addresses are public via `NewStaker` events and the `stakers` vector).
2. Paying Starknet gas once per block — economically feasible given Starknet's low fees.

No privileged access, no leaked key, and no external dependency is needed. The attacker gains nothing financially, making this a pure griefing vector, but the cost to sustain it is low relative to the damage inflicted on the entire staker set.

### Recommendation
Restrict `update_rewards` to a trusted caller (e.g., the attestation contract, a designated sequencer address, or a specific role). Alternatively, remove the `disable_rewards` parameter from the public interface entirely and handle the "no rewards" case internally based on protocol state (e.g., `is_pre_consensus()`). At minimum, move the `last_reward_block` write to **after** the `disable_rewards` guard so that a call with `disable_rewards: true` does not consume the block's reward slot.

### Proof of Concept
1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. Attacker observes the mempool or simply submits at the start of each block.
3. Attacker calls `Staking::update_rewards(staker_address: <any_valid_staker>, disable_rewards: true)`.
4. `last_reward_block` is set to the current block number; the function returns early without distributing rewards.
5. Any legitimate staker or sequencer that calls `update_rewards` in the same block receives `REWARDS_ALREADY_UPDATED` and no rewards are distributed.
6. Repeating step 3 every block permanently prevents all stakers and pool members from accumulating consensus yield.

### Citations

**File:** src/staking/staking.cairo (L1448-1452)
```text
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
