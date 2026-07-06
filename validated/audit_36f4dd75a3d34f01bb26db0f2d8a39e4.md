### Title
Unprivileged Caller Can Permanently Freeze All Staker Yield via `disable_rewards` Flag in `update_rewards` - (File: src/staking/staking.cairo)

### Summary
The public `update_rewards` function in the Staking contract accepts a caller-controlled `disable_rewards` boolean flag with no access control. Because the global `last_reward_block` checkpoint is written **before** the `disable_rewards` guard is evaluated, any unprivileged address can call `update_rewards(valid_staker, disable_rewards: true)` once per block to consume the block's single reward slot while distributing zero rewards. Repeated across every block, this permanently freezes all staker and delegator yield.

### Finding Description
`StakingRewardsManagerImpl::update_rewards` is a public entry point with no role check beyond `general_prerequisites` (pause + non-zero caller). Its logic is:

```
// src/staking/staking.cairo L1453-1506
fn update_rewards(ref self, staker_address, disable_rewards: bool) {
    self.general_prerequisites();                                   // only checks pause
    let current_block_number = starknet::get_block_number();
    assert!(current_block_number > self.last_reward_block.read(),  // one call per block
            Error::REWARDS_ALREADY_UPDATED);
    ...
    self.last_reward_block.write(current_block_number);            // ← slot consumed HERE
    if disable_rewards || self.is_pre_consensus() {
        return;                                                     // ← no rewards distributed
    }
    ...
    self._update_rewards(...);
}
``` [1](#0-0) 

The `last_reward_block` field is a **global** (not per-staker) counter. Once it is written for block `N`, the assertion `current_block_number > last_reward_block` prevents any further call in block `N`. Because the write happens unconditionally before the `disable_rewards` branch, a caller who passes `disable_rewards: true` burns the slot for the entire block without triggering `_update_rewards`. [2](#0-1) 

There is no check that the caller is the staker, the staker's operational address, or any privileged role.

### Impact Explanation
In the consensus-rewards phase (`is_pre_consensus() == false`), every block is worth a discrete `(strk_block_rewards, btc_block_rewards)` payout computed from the minting curve. If the reward slot for a block is consumed with `disable_rewards: true`, those block rewards are never credited to any staker's `unclaimed_rewards_own` and never forwarded to any delegation pool. The `RewardSupplier.unclaimed_rewards` counter is also never incremented for that block, so the tokens remain locked in the supplier with no accounting entry to claim them.

An attacker who calls this function every block causes **permanent, protocol-wide freezing of unclaimed yield** for all stakers and all pool members — matching the "Permanent freezing of unclaimed yield" High-severity impact. [3](#0-2) 

### Likelihood Explanation
The entry point is fully public, requires only a valid (active, non-zero-balance) staker address as argument, and costs only gas. Any address can monitor the chain and front-run legitimate `update_rewards` calls each block. The attacker has no financial risk and gains a competitive advantage (e.g., a rival staker suppressing competitors' yield). Likelihood is **High**.

### Recommendation
1. **Remove the `disable_rewards` parameter from the public interface**, or gate it behind a privileged role (e.g., `only_security_agent`).
2. Alternatively, move the `self.last_reward_block.write(current_block_number)` call to **after** the `disable_rewards` guard so that a no-op call does not consume the block slot.
3. Consider making `update_rewards` callable only by the staker's registered operational address or a whitelisted sequencer role.

### Proof of Concept
```
// Attacker script (pseudo-code, runs every block)
loop {
    // Pick any currently-active staker address
    let victim_staker = staking.stakers[0];
    // Consume the block reward slot with zero distribution
    staking.update_rewards(victim_staker, disable_rewards: true);
    // Result: last_reward_block == current_block, no rewards minted
    wait_for_next_block();
}
```

Step-by-step:
1. Attacker calls `update_rewards(valid_staker, disable_rewards: true)` at block `N`.
2. `general_prerequisites` passes (contract not paused, caller non-zero).
3. `current_block_number (N) > last_reward_block` assertion passes.
4. `last_reward_block` is written to `N`.
5. `disable_rewards == true` → function returns early; `_update_rewards` is never called.
6. Any legitimate call to `update_rewards` in block `N` now reverts with `REWARDS_ALREADY_UPDATED`.
7. Repeated every block → all staker and pool-member yield is permanently frozen. [4](#0-3) [5](#0-4)

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
