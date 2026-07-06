### Title
Any staker can monopolize all V3 consensus block rewards by front-running `update_rewards` every block - (File: src/staking/staking.cairo)

### Summary
In V3 consensus rewards mode, `update_rewards` is a fully public function with no access control beyond "caller is not zero." A global `last_reward_block` variable prevents more than one call per block, but since any staker can call it for themselves, an attacker who calls `update_rewards(attacker_address, false)` in every block receives 100% of all block rewards while every other staker receives nothing.

### Finding Description
`update_rewards` in `src/staking/staking.cairo` is the sole reward-distribution entry point in V3 (post-consensus) mode. Its only guards are `general_prerequisites()` (not paused, caller ≠ zero) and the single-call-per-block check on `last_reward_block`. [1](#0-0) 

There is no check that the caller is the staker, the staker's operational address, or that the staker is the one assigned to the current block by the protocol's staking-power-based assignment.

Once `last_reward_block` is written, no other staker can receive rewards for that block: [2](#0-1) 

In V3 mode the reward calculation passes the **staker's own total balance** as the denominator (`strk_total_stake`), not the global total stake: [3](#0-2) 

This means the called staker always receives 100% of the block's STRK rewards (split proportionally between their own balance and their pool): [4](#0-3) 

An attacker who calls `update_rewards(attacker, false)` in every block therefore captures the entire reward stream, leaving every other staker with zero rewards for those blocks.

### Impact Explanation
**High — Theft of unclaimed yield.** All newly minted block rewards (unclaimed yield) are diverted to the attacker. Every other staker permanently loses their proportional share of rewards for every block the attacker front-runs. The stolen amount scales with the total protocol inflation rate and the number of blocks the attacker covers.

### Likelihood Explanation
**High.** The attacker only needs to be a registered staker (stake ≥ `min_stake`) and run a simple bot that submits `update_rewards(attacker, false)` on every new block. Because the attacker receives 100% of block rewards regardless of their stake size, the profit vastly exceeds gas costs even with a minimal stake. No privileged role, leaked key, or external dependency is required.

### Recommendation
Restrict `update_rewards` so that only the staker (or their registered operational address) can call it for themselves. Alternatively, enforce the block-assignment rule already used in the attestation contract — derive the staker's assigned block from their staking power (analogous to `_calculate_target_attestation_block`) and assert that the current block matches before distributing rewards. [5](#0-4) 

### Proof of Concept
1. Attacker stakes the minimum amount (`min_stake`) to register as a staker.
2. Attacker waits K = 2 epochs for their stake to become effective.
3. Attacker runs a bot that submits `update_rewards(attacker_address, false)` on the first transaction of every block.
4. `last_reward_block` is set to the current block number; no other staker can call `update_rewards` in that block.
5. The reward calculation uses `staker_total_strk_balance` (attacker's own balance) as the denominator, so the attacker receives 100% of `strk_block_rewards` for that block.
6. Repeated every block, the attacker drains the entire reward stream; all other stakers accumulate zero unclaimed yield.

### Citations

**File:** src/staking/staking.cairo (L1449-1486)
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

```

**File:** src/staking/staking.cairo (L1493-1506)
```text
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
```

**File:** src/staking/staking.cairo (L1905-1924)
```text
        fn calculate_staker_own_rewards(
            self: @ContractState,
            staker_address: ContractAddress,
            strk_total_rewards: Amount,
            strk_total_stake: NormalizedAmount,
            curr_epoch: Epoch,
        ) -> Amount {
            let own_balance_curr_epoch = self
                .get_staker_own_balance_at_epoch(:staker_address, epoch_id: curr_epoch);
            // In V3 (consensus rewards), this error is unreachable since `update_rewards` is not
            // valid for stakers without balance.
            assert!(own_balance_curr_epoch.is_non_zero(), "{}", Error::ATTEST_WITH_ZERO_BALANCE);

            mul_wide_and_div(
                lhs: strk_total_rewards,
                rhs: own_balance_curr_epoch.to_strk_native_amount(),
                div: strk_total_stake.to_strk_native_amount(),
            )
                .expect_with_err(err: InternalError::REWARDS_COMPUTATION_OVERFLOW)
        }
```

**File:** src/attestation/attestation.cairo (L221-239)
```text
        fn _calculate_target_attestation_block(
            self: @ContractState, staking_attestation_info: StakingAttestationInfo,
        ) -> BlockNumber {
            // Compute staker hash for the attestation.
            let hash = PoseidonTrait::new()
                .update(staking_attestation_info.stake().into())
                .update(staking_attestation_info.epoch_id().into())
                .update(staking_attestation_info.staker_address().into())
                .finalize();
            // Calculate staker's block number in this epoch.
            let attestation_window = self.attestation_window.read();
            let block_offset: u256 = hash
                .into() % (staking_attestation_info.epoch_len() - attestation_window.into())
                .into();
            // Calculate actual block number for attestation.
            let target_attestation_block = staking_attestation_info.current_epoch_starting_block()
                + block_offset.try_into().unwrap();
            target_attestation_block
        }
```
