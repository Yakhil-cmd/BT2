### Title
Missing Access Control on `update_rewards` Enables Permanent Griefing of Staker Yield — (File: `src/staking/staking.cairo`)

### Summary
The `update_rewards` function is specified to be callable only by the Starkware sequencer, but the implementation enforces no such restriction. A global `last_reward_block` lock prevents more than one call per block. Any unprivileged address can front-run the sequencer with `disable_rewards: true`, consuming the block's reward slot and permanently destroying that block's yield for all stakers and delegators.

### Finding Description
The specification for `update_rewards` explicitly states:

> **Access control:** Only starkware sequencer. [1](#0-0) 

The implementation, however, only calls `general_prerequisites()`: [2](#0-1) 

`general_prerequisites()` only checks that the contract is unpaused and the caller is non-zero — no sequencer identity check exists anywhere: [3](#0-2) 

The critical design detail is that `last_reward_block` is a **global** (not per-staker) storage variable. It is written unconditionally before the `disable_rewards` branch: [4](#0-3) 

This means:
1. Calling `update_rewards(any_valid_staker, disable_rewards: true)` sets `last_reward_block = current_block` and returns immediately — no rewards are distributed.
2. Any subsequent call in the same block (including the legitimate sequencer call) reverts with `REWARDS_ALREADY_UPDATED`.
3. The block's reward allocation is permanently lost; there is no catch-up mechanism.

The `calculate_block_rewards` path — which updates `avg_block_duration` via `update_current_epoch_block_rewards` — is also bypassed, leaving the epoch's block-reward rate stale at the previous epoch's value: [5](#0-4) [6](#0-5) 

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

Each block for which the attacker front-runs the sequencer results in zero rewards credited to `unclaimed_rewards_own` for the targeted staker and zero STRK transferred to delegation pools. Because `last_reward_block` is a global lock and there is no retroactive reward mechanism, the yield for that block is destroyed permanently. Sustained execution across every block eliminates all staker and delegator yield indefinitely.

### Likelihood Explanation
**Medium.** The attacker requires no privileged role, no capital, and no oracle manipulation. The only requirement is the ability to submit a transaction that lands before the sequencer's `update_rewards` call in a given block. On Starknet, where the sequencer ordering is observable, this is a realistic griefing vector. The attacker pays gas but earns nothing — a pure griefing scenario.

### Recommendation
Add a caller check inside `update_rewards` that restricts execution to the designated Starkware sequencer address (stored in contract configuration), consistent with the specification. For example:

```cairo
fn update_rewards(ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    ...
}
```

### Proof of Concept
1. Attacker observes a block being produced on Starknet.
2. Attacker calls `IStakingRewardsManager::update_rewards(valid_staker_address, disable_rewards: true)` — any non-zero caller is accepted.
3. `last_reward_block` is set to the current block number; the function returns with no rewards distributed.
4. The Starkware sequencer's legitimate call to `update_rewards(staker_address, disable_rewards: false)` reverts with `REWARDS_ALREADY_UPDATED`.
5. `unclaimed_rewards_own` for the staker is unchanged; delegation pool balances are unchanged; the block's yield is permanently lost.
6. Repeating this every block eliminates all staker and delegator yield for the duration of the attack. [7](#0-6)

### Citations

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

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

**File:** src/staking/staking.cairo (L1558-1571)
```text
        fn calculate_block_rewards(
            ref self: ContractState,
            reward_supplier_dispatcher: IRewardSupplierDispatcher,
            curr_epoch: Epoch,
        ) -> (Amount, Amount) {
            if curr_epoch > self.last_calculated_epoch.read() {
                self.last_calculated_epoch.write(curr_epoch);
                let block_rewards = reward_supplier_dispatcher.update_current_epoch_block_rewards();
                self.block_rewards.write(block_rewards);
                block_rewards
            } else {
                self.block_rewards.read()
            }
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

**File:** src/reward_supplier/reward_supplier.cairo (L166-187)
```text
        fn update_current_epoch_block_rewards(ref self: ContractState) -> (Amount, Amount) {
            let staking_contract = self.staking_contract.read();
            assert!(
                get_caller_address() == staking_contract,
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );
            self.set_avg_block_duration();
            // Calculate block rewards for the current epoch.
            let minting_curve_dispatcher = self.minting_curve_dispatcher.read();
            let yearly_mint = minting_curve_dispatcher.yearly_mint();
            let avg_block_duration = self.avg_block_duration.read();
            let total_rewards = mul_wide_and_div(
                lhs: yearly_mint,
                rhs: avg_block_duration.into(),
                div: BLOCK_DURATION_SCALE.into() * SECONDS_IN_YEAR.into(),
            )
                .expect_with_err(err: InternalError::REWARDS_COMPUTATION_OVERFLOW);
            let btc_rewards = calculate_btc_rewards(:total_rewards);
            let strk_rewards = total_rewards - btc_rewards;
            (strk_rewards, btc_rewards)
        }
```
