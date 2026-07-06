### Title
Unprivileged Caller Can Permanently Freeze Staker Consensus Rewards via `disable_rewards` Flag - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in `Staking.cairo` is publicly callable with no access control beyond a non-zero caller check. It accepts a caller-controlled `disable_rewards: bool` parameter. When `true`, the function still writes the current block number to `last_reward_block`, consuming the block's reward slot, but skips all reward distribution. Any unprivileged actor can front-run every legitimate `update_rewards` call with `disable_rewards: true`, permanently denying a staker all consensus-phase block rewards.

### Finding Description

`update_rewards` is exposed as part of `IStakingRewardsManager` with `#[abi(embed_v0)]`, making it callable by any non-zero address: [1](#0-0) 

The function's only gate is `general_prerequisites()`, which checks pause state and non-zero caller — no role, no staker-only restriction: [2](#0-1) 

Critically, `last_reward_block` is written **before** the `disable_rewards` branch is evaluated: [3](#0-2) 

Because the function asserts `current_block_number > self.last_reward_block.read()`, once the slot is consumed with `disable_rewards: true`, no second call can distribute rewards for that same block: [4](#0-3) 

The `_update_rewards` path that actually credits `staker_info.unclaimed_rewards_own` and forwards pool rewards is never reached: [5](#0-4) 

### Impact Explanation

An attacker who calls `update_rewards(victim_staker, disable_rewards: true)` once per block permanently destroys that block's reward for the victim. Repeating this every block freezes the staker's `unclaimed_rewards_own` at zero indefinitely and starves all delegation pools of their share. This constitutes **permanent freezing of unclaimed yield** (High impact) and, because the rewards are never accrued rather than merely delayed, is equivalent to **theft of unclaimed yield**.

### Likelihood Explanation

The attack is cheap on Starknet (low gas), requires no special privilege, no leaked key, and no external dependency. The attacker only needs to monitor the chain and submit one transaction per block targeting any staker. The consensus-rewards phase (`consensus_rewards_first_epoch` set) is the only prerequisite, and that epoch is already configured on mainnet.

### Recommendation

Restrict `update_rewards` so that only the staker themselves, their operational address, or a designated consensus/sequencer role may call it. Alternatively, remove the `disable_rewards` parameter from the public interface entirely — the existing guards (`is_staker_active`, non-zero balance check) already handle the cases where rewards should not be distributed. If `disable_rewards` must remain, gate it behind a privileged role check analogous to `only_app_governor`.

### Proof of Concept

1. Staker `S` stakes and waits for the consensus rewards epoch to begin.
2. Each block, attacker `A` (any EOA) calls:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
3. `last_reward_block` is set to the current block number.
4. Any subsequent call by `S` or a validator in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. `S.unclaimed_rewards_own` never increases; all delegation pools receive zero rewards.
6. Repeating step 2 every block results in `S` earning zero rewards for the entire duration of the attack, with no on-chain mechanism for `S` to prevent it. [6](#0-5)

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

**File:** src/staking/staking.cairo (L2349-2365)
```text
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
```
