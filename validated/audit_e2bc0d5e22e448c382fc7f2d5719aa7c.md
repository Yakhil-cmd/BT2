### Title
Unprivileged Caller Can Suppress Reward Distribution via `disable_rewards` Flag in `update_rewards` - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the Staking contract accepts a caller-controlled `disable_rewards: bool` parameter with no access-control check. Any non-zero address can call `update_rewards(valid_staker, disable_rewards: true)` once per block, consuming the global `last_reward_block` slot while skipping all reward distribution. Because `last_reward_block` is a single global value, one such call per block permanently blocks every staker from receiving consensus-phase block rewards for that block.

### Finding Description
`update_rewards` is a public function gated only by `general_prerequisites()`, which checks that the contract is not paused and the caller is not the zero address. [1](#0-0) 

The function first validates that the current block has not already been processed: [2](#0-1) 

After validating the staker is active and has non-zero balance, it unconditionally writes `last_reward_block` to the current block number: [3](#0-2) 

The `disable_rewards` flag is then checked **after** the write, causing an early return with no reward distribution: [4](#0-3) 

Because `last_reward_block` is a single global storage slot shared across all stakers, any caller who wins the race at the start of a block with `disable_rewards: true` prevents every staker from receiving rewards for that block. No subsequent call in the same block can pass the `current_block_number > last_reward_block` guard. [2](#0-1) 

`general_prerequisites` imposes no role restriction: [5](#0-4) 

### Impact Explanation
An attacker who calls `update_rewards(any_valid_active_staker, disable_rewards: true)` once per block permanently freezes all consensus-phase block rewards for all stakers. Stakers accumulate zero `unclaimed_rewards_own` and pool contracts receive zero reward updates. This constitutes **permanent freezing of unclaimed yield** for the entire protocol as long as the attack is sustained, matching the High-impact category.

### Likelihood Explanation
The attack requires only:
1. Knowledge of any active staker address with non-zero balance — trivially obtained from on-chain `NewStaker` events.
2. Submitting one transaction per block before any legitimate `update_rewards` call.

No funds, no privileged role, and no special setup are needed. The cost is gas per block; the attacker has no profit motive but causes direct, measurable harm to all stakers.

### Recommendation
Restrict who may pass `disable_rewards: true`. Either:
- Add a role check (e.g., `only_security_agent`) before accepting `disable_rewards: true`, or
- Move the `last_reward_block` write to occur **only** when rewards are actually distributed (i.e., after the `disable_rewards` guard), so a suppressed call does not consume the block slot.

### Proof of Concept
1. Staker Alice stakes and becomes active with non-zero balance.
2. Attacker Bob monitors the mempool / block production.
3. At the start of each new block, Bob calls:
   ```
   staking.update_rewards(alice_address, disable_rewards: true)
   ```
4. The call passes all checks, writes `last_reward_block = current_block`, and returns early — no rewards distributed.
5. Any subsequent call by Alice or anyone else in the same block reverts with `REWARDS_ALREADY_UPDATED`.
6. Repeated every block, all stakers receive zero consensus block rewards indefinitely. [6](#0-5)

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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
