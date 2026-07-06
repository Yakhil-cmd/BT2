### Title
Missing Caller Validation in `update_rewards` Allows Any Address to Permanently Deny Consensus Rewards - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the staking contract is specified to be callable only by the Starknet sequencer, but no on-chain caller check is enforced. Any unprivileged address can call it with `disable_rewards: true`, consuming the global `last_reward_block` slot for the current block and permanently preventing legitimate reward distribution for that block. Repeated every block, this permanently freezes all stakers' unclaimed consensus-era yield.

### Finding Description
The spec at `docs/spec.md` line 1645 states the access control for `update_rewards` is **"Only starkware sequencer"**. However, the implementation at `src/staking/staking.cairo` lines 1449–1507 only calls `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero — no sequencer identity check is performed. [1](#0-0) 

`general_prerequisites()` is defined as: [2](#0-1) 

The function accepts a caller-controlled `disable_rewards: bool` parameter. When `disable_rewards` is `true`, the function writes the current block number to the global `last_reward_block` storage slot and returns immediately without distributing any rewards: [3](#0-2) 

Because `last_reward_block` is a single global value (not per-staker), the guard at line 1454–1458 prevents any second call to `update_rewards` in the same block: [4](#0-3) 

The spec confirms this is a global, per-block constraint: [5](#0-4) 

### Impact Explanation
An attacker who calls `update_rewards(staker_address: <any_active_staker>, disable_rewards: true)` every block:

1. Consumes the single allowed `update_rewards` slot for that block.
2. Writes `last_reward_block = current_block`, causing every subsequent call in the same block to revert with `REWARDS_ALREADY_UPDATED`.
3. The legitimate sequencer's call is blocked; no staker receives block rewards for that block.
4. Repeated indefinitely, this permanently freezes all unclaimed consensus-era yield for all stakers and their delegators.

This matches the allowed impact: **High — Permanent freezing of unclaimed yield**.

### Likelihood Explanation
The entry point is a public, permissionless function on the staking contract. Any address with enough gas can call it. No token balance, staker registration, or privileged role is required. The attacker only needs to submit a transaction before the sequencer's own `update_rewards` transaction in each block. Because the sequencer controls ordering, it could theoretically self-protect, but this is an off-chain operational assumption — the contract itself provides no on-chain guarantee. The cost to the attacker is only gas per block.

### Recommendation
Add an explicit on-chain check that `get_caller_address() == get_sequencer_address()` (or an equivalent stored sequencer address) at the top of `update_rewards`, consistent with the spec's stated access control. This mirrors the pattern already used for other privileged callers in the codebase (e.g., `CALLER_IS_NOT_STAKING_CONTRACT` checks in `reward_supplier.cairo`). [6](#0-5) 

### Proof of Concept

1. Deploy the system normally; advance K epochs so a staker has active balance and consensus rewards are live.
2. From any unprivileged address `ATTACKER`, call every block:
   ```
   IStakingRewardsManagerDispatcher { contract_address: staking_contract }
       .update_rewards(staker_address: any_active_staker, disable_rewards: true);
   ```
3. Observe that `last_reward_block` is set to the current block number.
4. The legitimate sequencer's `update_rewards` call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. After N blocks, `staker_info.unclaimed_rewards_own` remains zero despite N blocks of elapsed consensus time — all yield is permanently frozen. [7](#0-6)

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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** docs/spec.md (L1638-1645)
```markdown
1. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
2. [REWARDS\_ALREADY\_UPDATED](#rewards_already_updated)
3. [STAKER\_NOT\_EXISTS](#staker_not_exists)
4. [INVALID\_STAKER](#invalid_staker)
#### pre-condition <!-- omit from toc -->
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/reward_supplier/reward_supplier.cairo (L192-196)
```text
            assert!(
                get_caller_address() == self.staking_contract.read(),
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );
```
