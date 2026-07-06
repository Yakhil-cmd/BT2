### Title
Unpermissioned `update_rewards` Caller Can Permanently Freeze Consensus Rewards by Passing `disable_rewards: true` - (File: src/staking/staking.cairo)

### Summary

`IStakingRewardsManager::update_rewards` is a public function with no access-control guard. It accepts a caller-controlled `disable_rewards: bool` parameter. Critically, it writes the current block number to `last_reward_block` **before** checking `disable_rewards`, so when an attacker calls it with `disable_rewards: true`, the block is "consumed" and no legitimate caller can distribute rewards for that block. Repeating this every block permanently freezes all consensus-phase staker rewards.

### Finding Description

`update_rewards` is exposed as a public entry point under `IStakingRewardsManager`: [1](#0-0) 

The only gate is `general_prerequisites()`, which only checks that the contract is not paused and the caller is non-zero: [2](#0-1) 

Inside `update_rewards`, the global `last_reward_block` is written **before** the `disable_rewards` branch: [3](#0-2) 

After that write, the function checks `disable_rewards` and returns early if it is `true`, skipping the entire reward-distribution path: [4](#0-3) 

Because `last_reward_block` is now equal to the current block, the guard at the top of the function will reject any subsequent call in the same block: [5](#0-4) 

The attacker therefore needs only to call `update_rewards(any_active_staker, disable_rewards: true)` once per block to permanently prevent all consensus rewards from ever being distributed.

### Impact Explanation

Every block in which the attacker fires the call, the `last_reward_block` slot is consumed and `_update_rewards` is never reached. No staker accumulates `unclaimed_rewards_own` for that block, and no pool receives its share. If sustained across all blocks, **all consensus-phase staker and delegator yield is permanently frozen** — matching the "Permanent freezing of unclaimed yield" High-severity impact. [6](#0-5) 

### Likelihood Explanation

- The attacker needs no privileged role, no stake, and no special knowledge beyond the address of any currently active staker (public on-chain data).
- The cost is one cheap Starknet transaction per block.
- The attack is silent: no revert, no anomalous event — only missing reward events.
- The attack is effective only after `consensus_rewards_first_epoch` is set (pre-consensus rewards flow through the attestation path), but that is the production steady-state.

### Recommendation

Restrict `update_rewards` to a single authorized caller (e.g., the consensus contract or a dedicated sequencer role), mirroring how `update_rewards_from_attestation_contract` is restricted to the attestation contract: [7](#0-6) 

Alternatively, remove the `disable_rewards` parameter from the public interface entirely and derive the "should rewards be disabled" decision from on-chain state (e.g., whether the staker performed their consensus duties), so no external caller can inject that decision.

### Proof of Concept

1. Consensus rewards are active (`consensus_rewards_first_epoch` has been set and the current epoch ≥ that value).
2. Attacker identifies any active staker `S` with non-zero STRK balance (readable from `staker_info` / `staker_own_balance_trace`).
3. At the start of every block, attacker submits:
   ```
   staking_contract.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. The function passes `general_prerequisites()`, passes the staker-active checks, writes `last_reward_block = current_block`, then hits `if disable_rewards { return; }` and exits without calling `_update_rewards`.
5. Any honest caller attempting `update_rewards` in the same block hits `REWARDS_ALREADY_UPDATED` and reverts.
6. No staker or pool accumulates rewards for that block. Repeated every block, all consensus yield is permanently frozen. [8](#0-7)

### Citations

**File:** src/staking/staking.cairo (L1394-1401)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

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
