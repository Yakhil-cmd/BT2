### Title
Global `last_reward_block` Enables Griefing of Consensus Rewards via Unprivileged `update_rewards` Call - (File: `src/staking/staking.cairo`)

### Summary
The `update_rewards` function uses a single global `last_reward_block` storage variable to gate reward distribution. Because this variable is not scoped per-staker and `update_rewards` is callable by any unprivileged address, a malicious actor can call `update_rewards(valid_staker, disable_rewards: true)` in every block to consume the block's reward slot without distributing rewards, blocking all stakers from receiving consensus-era rewards.

### Finding Description
In `src/staking/staking.cairo`, `update_rewards` enforces a single-call-per-block invariant using a global `last_reward_block` variable:

```rust
assert!(current_block_number > self.last_reward_block.read(), "{}", Error::REWARDS_ALREADY_UPDATED);
...
self.last_reward_block.write(current_block_number);
if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [1](#0-0) 

`last_reward_block` is a single global storage variable — not a per-staker mapping. Any call to `update_rewards`, regardless of the `staker_address` argument or the `disable_rewards` flag, writes the current block number to `last_reward_block`. This means:

1. Only one `update_rewards` call can succeed per block across **all** stakers.
2. A call with `disable_rewards: true` still consumes the block's reward slot without distributing any rewards.
3. `update_rewards` has no access control beyond `general_prerequisites()` (unpaused + non-zero caller). [2](#0-1) 

An attacker calls `update_rewards(any_valid_staker, disable_rewards: true)` in every block, setting `last_reward_block` to the current block number. Any subsequent legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`, and no staker receives consensus rewards for that block.

The `update_rewards` interface confirms it is open to any caller: [3](#0-2) 

This is the direct analog to the external report's root cause: a "latest-only" global state (`last_reward_block` ↔ `provenStates[chainId]`) that any unprivileged actor can overwrite, invalidating in-progress legitimate operations.

### Impact Explanation
This is a griefing attack with no profit motive but direct damage to stakers: all stakers are denied their consensus-era block rewards for every block in which the attacker front-runs. If sustained, this constitutes a **permanent freezing of unclaimed yield** for all stakers in the consensus rewards phase. This matches the allowed High impact: *"Permanent freezing of unclaimed yield or unclaimed royalties; Temporary freezing of funds."*

### Likelihood Explanation
The attack requires no special privileges — any address can call `update_rewards`. The attacker must front-run legitimate calls in each block, paying gas per block. On Starknet, transaction ordering is determined by the sequencer, so the attacker must

### Citations

**File:** src/staking/staking.cairo (L1447-1508)
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
