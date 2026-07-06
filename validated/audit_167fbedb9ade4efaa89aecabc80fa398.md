### Title
Unrestricted `update_rewards` Allows Any Caller to Permanently Freeze Staker Yield via `disable_rewards` Flag - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the `Staking` contract is callable by any unprivileged address. It accepts a `disable_rewards: bool` parameter that, when `true`, advances the global `last_reward_block` checkpoint without distributing any rewards. Because `last_reward_block` is a single global slot, one call per block is sufficient to permanently block the legitimate consensus mechanism from distributing rewards for that block.

### Finding Description
`update_rewards` is exposed as a public entry point under `StakingRewardsManagerImpl`. Its only access gate is `general_prerequisites`, which checks only that the contract is not paused and that the caller is non-zero. [1](#0-0) 

`general_prerequisites` contains no role check: [2](#0-1) 

The function unconditionally writes `current_block_number` to `last_reward_block` before branching on `disable_rewards`: [3](#0-2) 

When `disable_rewards` is `true`, execution returns immediately after updating `last_reward_block`, skipping all reward computation and distribution: [4](#0-3) 

Because `last_reward_block` is a single global storage slot shared across all stakers, any subsequent call in the same block — including the legitimate consensus mechanism — will revert with `REWARDS_ALREADY_UPDATED`: [5](#0-4) 

### Impact Explanation
An attacker who front-runs the consensus mechanism's `update_rewards` call every block with `disable_rewards: true` causes every block's STRK and BTC consensus rewards to be permanently skipped. The rewards for a given block are never re-queued; once `last_reward_block` advances past a block, that block's yield is irrecoverably lost for all stakers and pool members. This constitutes **permanent freezing of unclaimed yield** for the entire protocol.

### Likelihood Explanation
The attack requires only a valid staker address (readable from the public `stakers` vector) and enough gas to submit one transaction per block. On Starknet, transaction fees are low. No privileged key, no token approval, and no prior stake is required. The attacker has no profit motive but can inflict continuous, irreversible yield loss on all participants.

### Recommendation
Restrict `update_rewards` to a trusted caller — either the attestation contract, a designated consensus role, or the block proposer address. Add a role check analogous to the one used in `update_rewards_from_attestation_contract`: [6](#0-5) 

Alternatively, remove the `disable_rewards` parameter from the public interface and handle the "no reward" case internally based on on-chain conditions rather than caller-supplied input.

### Proof of Concept
1. Attacker observes the mempool or simply submits a transaction at the start of every block.
2. Attacker calls `update_rewards(staker_address=<any_active_staker>, disable_rewards=true)`.
3. `general_prerequisites` passes (contract not paused, caller non-zero).
4. `last_reward_block` is set to the current block number.
5. The function returns early — no rewards are computed or transferred.
6. The legitimate consensus mechanism's `update_rewards` call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
7. Repeated every block, all consensus-epoch rewards are permanently frozen for every staker and pool member in the protocol. [1](#0-0)

### Citations

**File:** src/staking/staking.cairo (L1399-1401)
```text
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
