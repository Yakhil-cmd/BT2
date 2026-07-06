### Title
Unprotected `disable_rewards` Parameter in `update_rewards` Allows Any Caller to Permanently Freeze Block Rewards for All Stakers - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the `Staking` contract is publicly callable with no access control. It accepts a caller-controlled `disable_rewards: bool` parameter. When set to `true`, the function consumes the global `last_reward_block` slot for the current block and returns early without distributing any rewards. Because `last_reward_block` is a single global value, any unprivileged attacker can call `update_rewards(any_valid_staker, true)` once per block to permanently prevent all stakers from ever receiving consensus-mode block rewards.

### Finding Description

`update_rewards` is exposed as a public ABI function under `IStakingRewardsManager`. Its only caller gate is `general_prerequisites`, which checks that the contract is not paused and the caller is not the zero address. [1](#0-0) 

The function immediately writes the current block number to the global `last_reward_block` storage variable before checking `disable_rewards`: [2](#0-1) 

If `disable_rewards` is `true`, the function returns without distributing any rewards: [3](#0-2) 

Because `last_reward_block` is global (not per-staker), the guard at the top of the function: [4](#0-3) 

ensures that only one `update_rewards` call can succeed per block. Once an attacker calls `update_rewards(valid_staker, true)`, no legitimate call can succeed in the same block. The attacker repeats this every block, and block rewards are permanently lost for all stakers.

The actual reward distribution path that is bypassed: [5](#0-4) 

The `_update_rewards` internal function, which credits `unclaimed_rewards_own` to stakers and forwards rewards to delegation pools, is never reached. [6](#0-5) 

### Impact Explanation

This is a **permanent freezing of unclaimed yield**. In consensus-rewards mode (after `consensus_rewards_first_epoch` is set), `update_rewards` is the sole mechanism for distributing per-block STRK rewards to stakers and their delegation pools. An attacker who calls `update_rewards(valid_staker, true)` every block ensures that `staker_info.unclaimed_rewards_own` is never incremented and `update_pool_rewards` is never called. All stakers and pool members are permanently denied their earned block rewards. The rewards are not redirected — they are simply never minted/claimed from the reward supplier.

### Likelihood Explanation

Exploitation requires only:
1. A non-zero caller address (any EOA or contract).
2. Knowledge of any currently active staker address with non-zero balance (trivially obtained from on-chain events or `get_stakers`).
3. One transaction per block — a negligible gas cost relative to the value of rewards frozen.

There is no economic barrier, no privileged role required, and no dependency on external systems.

### Recommendation

Add an access-control check to `update_rewards` so that only an authorized caller (e.g., the block proposer, a designated rewards manager role, or the staker themselves) can invoke it. Alternatively, remove the `disable_rewards` parameter from the public interface entirely and handle the "no rewards" case internally based on on-chain conditions (e.g., `is_pre_consensus()`), rather than trusting a caller-supplied boolean.

### Proof of Concept

1. Consensus rewards are activated (`consensus_rewards_first_epoch` is set and the current epoch has passed it).
2. Attacker (any address `A != 0`) observes a valid active staker address `S` with non-zero STRK balance.
3. Each block, attacker calls: `staking.update_rewards(staker_address: S, disable_rewards: true)`.
4. Inside the call:
   - `current_block_number > last_reward_block` passes (new block).
   - `last_reward_block` is written to `current_block_number`.
   - `disable_rewards == true` → early return, no rewards distributed.
5. Any legitimate call to `update_rewards` in the same block fails with `REWARDS_ALREADY_UPDATED`.
6. Staker `S` (and all other stakers) accumulate zero `unclaimed_rewards_own` indefinitely. Pool members receive zero rewards via `update_rewards_from_staking_contract`. All block rewards are permanently frozen.

### Citations

**File:** src/staking/staking.cairo (L1448-1460)
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
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

**File:** src/staking/staking.cairo (L1491-1507)
```text
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
