Looking at the vulnerability class — **user-controlled parameter passed without validation, allowing manipulation of a critical protocol mechanism** — I need to find an analog in the Starknet Staking codebase where an unprivileged caller can pass an unvalidated value that disrupts reward distribution.

After reading `src/staking/staking.cairo` in full, I found a direct analog.

---

### Title
Unprivileged caller can permanently freeze all consensus rewards via unvalidated `disable_rewards` parameter in `update_rewards` — (File: `src/staking/staking.cairo`)

### Summary
The public `update_rewards` function accepts a caller-controlled `disable_rewards: bool` parameter. Any non-zero address can call it with `disable_rewards: true`, which advances the global `last_reward_block` to the current block **without distributing any rewards**. Because `last_reward_block` is a single global variable, this permanently blocks every staker from receiving consensus rewards for that block. Repeating this call every block freezes all unclaimed yield indefinitely.

### Finding Description
`StakingRewardsManagerImpl::update_rewards` is gated only by `general_prerequisites()`, which checks that the contract is not paused and the caller is non-zero — no role or identity check. [1](#0-0) 

The function writes `last_reward_block` to the current block number **before** evaluating `disable_rewards`: [2](#0-1) 

Then it branches on the caller-supplied flag: [3](#0-2) 

Because `last_reward_block` is a single global slot (not per-staker), once it is written for block `N`, the guard at the top of the function: [4](#0-3) 

causes every subsequent call in block `N` — including legitimate calls from stakers — to revert with `REWARDS_ALREADY_UPDATED`. The attacker only needs to supply any currently-active staker address with non-zero balance (all staker addresses are publicly enumerable from the `stakers` Vec in storage). [5](#0-4) 

### Impact Explanation
**Permanent freezing of unclaimed yield.** As long as the attacker calls `update_rewards(any_active_staker, disable_rewards: true)` once per block, no staker ever accumulates consensus-era block rewards. The `unclaimed_rewards_own` field in every `InternalStakerInfo` is never incremented, and pool reward traces are never updated, so neither stakers nor delegators can claim any yield. [6](#0-5) 

### Likelihood Explanation
**High.** The entry point is fully public, requires no privileged role, no token approval, and no stake. The attacker pays only Starknet gas per block. Active staker addresses are publicly readable from the `stakers` storage vector. The attack is trivially scriptable and has no prerequisite beyond a funded L2 account.

### Recommendation
Remove `disable_rewards` from the public ABI entirely, or gate the `disable_rewards: true` path behind a privileged role (e.g., `only_security_agent`). Alternatively, write `last_reward_block` only after the `disable_rewards` guard so that a skipped-reward call does not consume the block slot.

### Proof of Concept
1. Attacker identifies any active staker `S` with non-zero STRK balance (readable from public storage).
2. At the start of every block, attacker calls `staking.update_rewards(S, disable_rewards: true)`.
3. `last_reward_block` is set to the current block number; the function returns early — no rewards are computed or transferred.
4. Any legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. `staker_info.unclaimed_rewards_own` is never incremented; pool `cumulative_rewards_trace` is never updated.
6. All stakers and delegators are permanently unable to accumulate or claim consensus rewards.

### Citations

**File:** src/staking/staking.cairo (L1448-1507)
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

**File:** src/staking/staking.cairo (L2313-2376)
```text
        fn _update_rewards(
            ref self: ContractState,
            staker_address: ContractAddress,
            strk_total_rewards: Amount,
            btc_total_rewards: Amount,
            strk_total_stake: NormalizedAmount,
            btc_total_stake: NormalizedAmount,
            mut staker_info: InternalStakerInfoLatest,
            staker_pool_info: StoragePath<InternalStakerPoolInfoV2>,
            reward_supplier_dispatcher: IRewardSupplierDispatcher,
            curr_epoch: Epoch,
        ) {
            // Calculate self rewards.
            let staker_own_rewards = self
                .calculate_staker_own_rewards(
                    :staker_address, :strk_total_rewards, :strk_total_stake, :curr_epoch,
                );

            // Calculate pools rewards.
            let (commission_rewards, total_pools_rewards, pools_rewards_data) = if staker_pool_info
                .has_pool() {
                self
                    .calculate_staker_pools_rewards(
                        :staker_address,
                        :staker_pool_info,
                        :strk_total_rewards,
                        :strk_total_stake,
                        :btc_total_rewards,
                        :btc_total_stake,
                        :curr_epoch,
                    )
            } else {
                (Zero::zero(), Zero::zero(), array![])
            };

            // Update reward supplier.
            let staker_rewards = staker_own_rewards + commission_rewards;
            // Update total rewards.
            reward_supplier_dispatcher
                .update_unclaimed_rewards_from_staking_contract(
                    rewards: staker_rewards + total_pools_rewards,
                );
            // Claim pools rewards.
            claim_from_reward_supplier(
                :reward_supplier_dispatcher,
                amount: total_pools_rewards,
                token_dispatcher: strk_token_dispatcher(),
            );
            // Update staker rewards.
            staker_info.unclaimed_rewards_own += staker_rewards;

            // Update pools rewards.
            let pool_rewards_list = self.update_pool_rewards(:staker_address, :pools_rewards_data);
            // Emit event.
            self
                .emit(
                    Events::StakerRewardsUpdated {
                        staker_address, staker_rewards, pool_rewards: pool_rewards_list.span(),
                    },
                );

            // Write staker rewards to storage.
            self.write_staker_info(:staker_address, :staker_info);
        }
```
