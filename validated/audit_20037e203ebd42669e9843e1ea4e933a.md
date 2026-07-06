### Title
Unprivileged Caller Can Permanently Freeze Block Rewards by Calling `update_rewards` with `disable_rewards: true` - (File: src/staking/staking.cairo)

### Summary

`update_rewards` in `staking.cairo` is documented as "Only starkware sequencer" but has no caller access control in the implementation. Any non-zero address can call it with `disable_rewards: true`, which writes `last_reward_block` to the current block and returns early without distributing rewards. The legitimate sequencer call for that same block then reverts with `REWARDS_ALREADY_UPDATED`, permanently losing all block rewards for that block.

### Finding Description

`StakingRewardsManagerImpl::update_rewards` is the consensus-era reward distribution entry point. Its only gate is `general_prerequisites()`, which checks only that the contract is unpaused and the caller is non-zero — there is no sequencer identity check. [1](#0-0) 

The function body unconditionally writes `last_reward_block` to the current block number **before** branching on `disable_rewards`: [2](#0-1) 

If `disable_rewards == true`, the function returns immediately without distributing any rewards. Any subsequent call in the same block — including the legitimate sequencer call with `disable_rewards: false` — hits the guard: [3](#0-2) 

and reverts with `REWARDS_ALREADY_UPDATED`. The rewards for that block are never credited to any staker or pool and are permanently lost.

The spec explicitly states the intended access control: [4](#0-3) 

but the implementation does not enforce it.

### Impact Explanation

Every block for which the attacker front-runs the sequencer call loses its entire block reward allocation. Because `update_rewards` is the sole path through which consensus-era block rewards are credited (`_update_rewards` → `update_unclaimed_rewards_from_staking_contract`), the lost rewards are never minted or distributed. This constitutes **permanent freezing of unclaimed yield** for all stakers and delegators. [5](#0-4) 

### Likelihood Explanation

The attack requires only:
1. A valid active staker address — trivially obtained from on-chain `NewStaker` events.
2. Submitting a transaction before the sequencer's `update_rewards` call each block.

On Starknet, transaction ordering within a block is controlled by the sequencer, but the attacker can submit the griefing transaction at the start of each block. The cost is only gas per block. No capital, no privileged role, and no special knowledge is required. The attack can be automated to run continuously, permanently suppressing all consensus rewards.

### Recommendation

Add a sequencer-only access control check at the top of `update_rewards`, analogous to the `CALLER_IS_NOT_STAKING_CONTRACT` guard used in `RewardSupplier`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    // Add: assert caller is the designated sequencer/operator address
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    ...
}
```

Alternatively, move the `self.last_reward_block.write(current_block_number)` to after the `disable_rewards` branch so that a `disable_rewards: true` call does not consume the block's reward slot. [6](#0-5) 

### Proof of Concept

1. Consensus rewards are active (`!is_pre_consensus()`).
2. Attacker observes a valid active staker address `S` from chain events.
3. At the start of block `N`, attacker calls:
   ```
   update_rewards(staker_address: S, disable_rewards: true)
   ```
4. `general_prerequisites()` passes (contract unpaused, caller non-zero).
5. `current_block_number (N) > last_reward_block` — passes.
6. Staker `S` is active with non-zero balance — passes.
7. `last_reward_block` is written to `N`.
8. `disable_rewards == true` → early return, zero rewards distributed.
9. Sequencer calls `update_rewards(staker_address: S, disable_rewards: false)` for block `N`.
10. `current_block_number (N) > last_reward_block (N)` → **false** → reverts `REWARDS_ALREADY_UPDATED`.
11. All block rewards for block `N` are permanently lost.
12. Repeat every block to freeze all consensus rewards indefinitely. [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L1447-1507)
```text
    #[abi(embed_v0)]
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

            // Get current block data and update rewards.
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
            let (strk_block_rewards, btc_block_rewards) = self
                .calculate_block_rewards(:reward_supplier_dispatcher, :curr_epoch);
            self
                ._update_rewards(
                    :staker_address,
                    strk_total_rewards: strk_block_rewards,
                    btc_total_rewards: btc_block_rewards,
                    strk_total_stake: staker_total_strk_balance,
                    btc_total_stake: staker_total_btc_balance,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
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

**File:** src/staking/staking.cairo (L2348-2354)
```text
            // Update reward supplier.
            let staker_rewards = staker_own_rewards + commission_rewards;
            // Update total rewards.
            reward_supplier_dispatcher
                .update_unclaimed_rewards_from_staking_contract(
                    rewards: staker_rewards + total_pools_rewards,
                );
```

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
