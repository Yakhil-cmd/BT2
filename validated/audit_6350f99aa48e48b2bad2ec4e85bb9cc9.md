### Title
Missing Access Control on `update_rewards` Allows Any Caller to Suppress Block Reward Distribution - (File: src/staking/staking.cairo)

### Summary
`IStakingRewardsManager::update_rewards` in the Staking contract has no caller validation. It accepts a caller-controlled `disable_rewards: bool` flag and unconditionally writes the current block number to the global `last_reward_block` storage slot before checking that flag. Any unprivileged address can call this function with `disable_rewards: true` to consume the per-block reward slot without distributing rewards, permanently denying consensus block rewards for that block to all stakers.

### Finding Description
`update_rewards` is part of the public `IStakingRewardsManager` interface and carries no `assert_caller_is_*` guard. [1](#0-0) 

The function flow is:

1. Checks `current_block_number > last_reward_block` — passes once per block.
2. Validates that `staker_address` is an active staker (public information).
3. **Writes `last_reward_block = current_block_number`** — this is a global, not per-staker.
4. If `disable_rewards == true` **or** pre-consensus, returns immediately without distributing any rewards. [2](#0-1) 

Because `last_reward_block` is global and the check at step 1 is a strict greater-than, any subsequent legitimate call to `update_rewards` in the same block will revert with `REWARDS_ALREADY_UPDATED`. The attacker therefore needs only one successful call per block to permanently erase that block's reward distribution.

The `disable_rewards` parameter is structurally intended for the consensus layer to signal that a staker should not receive rewards for a given block (e.g., missed attestation). Without access control, this privileged semantic is exposed to every address on-chain. [3](#0-2) 

### Impact Explanation
An attacker who front-runs every legitimate `update_rewards` call with `update_rewards(any_valid_staker, disable_rewards: true)` causes:

- `last_reward_block` is advanced to the current block.
- No STRK or BTC block rewards are computed or forwarded to any staker or pool.
- All subsequent `update_rewards` calls in that block revert.

Repeated across blocks, this permanently freezes all unclaimed consensus-phase yield for every staker in the system. This matches the **High** impact category: *Permanent freezing of unclaimed yield*.

### Likelihood Explanation
- No special role, key, or privilege is required.
- The only precondition is knowing one valid, active staker address — all staker addresses are emitted as public `NewStaker` events.
- The attack is a simple front-run or independent call; it costs only gas.
- Likelihood is **High**.

### Recommendation
Restrict `update_rewards` to a trusted caller. The most natural choice is the Attestation contract (for pre-consensus) or the consensus layer contract (for post-consensus). Add a guard analogous to the existing `assert_caller_is_attestation_contract` pattern already used in `update_rewards_from_attestation_contract`: [4](#0-3) 

Concretely, add at the top of `update_rewards`:
```cairo
self.assert_caller_is_attestation_contract(); // or a dedicated consensus contract check
```

Alternatively, remove the `disable_rewards` parameter entirely and let the caller (attestation/consensus contract) simply not call `update_rewards` when rewards should be suppressed, keeping the function callable only by that trusted contract.

### Proof of Concept
1. Staker Alice is active. Her address is known from the `NewStaker` event.
2. Consensus rewards are active (`is_pre_consensus() == false`).
3. A new block `B` is produced. The legitimate consensus layer prepares to call `update_rewards(alice, disable_rewards: false)`.
4. Attacker front-runs with `update_rewards(alice, disable_rewards: true)`.
   - `current_block_number (B) > last_reward_block` → passes.
   - `last_reward_block` is written to `B`.
   - Function returns early; no rewards computed or sent.
5. Legitimate call arrives: `current_block_number (B) > last_reward_block (B)` → **false** → reverts with `REWARDS_ALREADY_UPDATED`.
6. Block `B`'s rewards are permanently lost for all stakers.
7. Repeat for every block. [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L1393-1401)
```text
    impl StakingAttestationImpl of IStakingAttestation<ContractState> {
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

**File:** src/staking/staking.cairo (L1448-1490)
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
