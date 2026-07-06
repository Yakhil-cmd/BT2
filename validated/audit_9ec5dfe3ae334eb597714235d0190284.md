### Title
Unprivileged Caller Can Permanently Freeze Consensus Rewards via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

### Summary

Any unprivileged caller can invoke `update_rewards` with `disable_rewards: true` on any valid staker, causing the contract to advance `last_reward_block` to the current block without distributing any rewards. Because the per-block guard prevents a second call in the same block, the rewards for that block are permanently lost for all stakers.

### Finding Description

`update_rewards` is a public function gated only by `general_prerequisites()`, which checks that the contract is not paused and the caller is not the zero address. No role or identity check restricts who may call it. [1](#0-0) 

The function accepts a caller-controlled `disable_rewards: bool` parameter. When `true`, the function writes the current block number to `last_reward_block` and returns immediately, skipping all reward computation and distribution. [2](#0-1) 

The per-block guard that follows enforces that `update_rewards` can only be called once per block: [3](#0-2) 

Because `last_reward_block` is a single global value shared across all stakers, a single call with `disable_rewards: true` for any valid staker exhausts the reward slot for the entire block. No subsequent call — by the legitimate staker or anyone else — can distribute rewards for that block.

The attacker only needs to supply any currently active staker address with non-zero STRK balance, both of which are publicly observable on-chain. [4](#0-3) 

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

In the consensus rewards phase (`is_pre_consensus() == false`), block rewards are the sole mechanism by which stakers and delegators accumulate yield. An attacker who calls `update_rewards(valid_staker, disable_rewards: true)` once per block eliminates all consensus rewards for every staker permanently. Even a single missed block represents an irrecoverable loss of yield. A sustained attack (one cheap L2 transaction per block) reduces total staker yield to zero.

### Likelihood Explanation

**High.** The function is fully public, requires no privileged role, and the only precondition is supplying a valid active staker address — trivially obtained from on-chain events (`NewStaker`). The gas cost on Starknet L2 is negligible. The attack requires no capital, no flash loan, and no coordination. A single bot can execute it continuously.

### Recommendation

1. **Restrict the caller**: Add an access-control check so that only a designated role (e.g., `REWARDS_UPDATER_ROLE`, or the sequencer/consensus layer address) may call `update_rewards`.
2. **Remove the `disable_rewards` parameter from the public interface**: If disabling rewards is a legitimate operational need, gate it behind a privileged role or derive it entirely from on-chain state rather than accepting it as a caller-supplied argument.
3. **Alternatively, move `last_reward_block` update after the rewards guard**: Only advance `last_reward_block` when rewards are actually computed and distributed, so a no-op call does not consume the block's reward slot.

### Proof of Concept

1. Consensus rewards phase is active (`consensus_rewards_first_epoch` has been set and the current epoch has passed it).
2. A new block `N` is produced. `last_reward_block < N`.
3. Attacker calls `staking.update_rewards(alice_staker, disable_rewards: true)`.
   - `general_prerequisites()` passes (contract not paused, caller non-zero).
   - `current_block_number (N) > last_reward_block` — guard passes.
   - `alice_staker` is active with non-zero balance — staker checks pass.
   - `last_reward_block` is written to `N`.
   - `disable_rewards == true` → function returns early; no rewards distributed.
4. Alice (or anyone) attempts `staking.update_rewards(alice_staker, disable_rewards: false)`.
   - `current_block_number (N) > last_reward_block (N)` → **false** → reverts with `REWARDS_ALREADY_UPDATED`.
5. Block `N`'s rewards are permanently lost for all stakers. Repeat for every block. [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L1449-1507)
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
