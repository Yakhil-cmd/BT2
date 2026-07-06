### Title
Missing Caller Authorization in `update_rewards` Allows Reward Misrouting to Arbitrary Staker - (File: src/staking/staking.cairo)

### Summary
`update_rewards` in the `StakingRewardsManagerImpl` accepts an arbitrary `staker_address` from any unprivileged caller with no check that the caller is authorized to trigger rewards for that staker. Because `last_reward_block` is a global variable updated on every call, an attacker can front-run the legitimate block proposer, redirect the entire block's STRK rewards to a staker of their choosing, and permanently deny the actual proposer their yield for that block.

### Finding Description
`update_rewards` is the V3 consensus-rewards entry point. It is callable by any non-zero address: [1](#0-0) 

`general_prerequisites()` enforces only "not paused" and "caller not zero": [2](#0-1) 

After validating that `staker_address` is an active staker with non-zero balance, the function immediately writes the current block number into the **global** `last_reward_block`: [3](#0-2) 

The guard at the top of the function prevents any second call in the same block: [4](#0-3) 

Once `last_reward_block` is stamped, the function computes per-block STRK/BTC rewards and credits them entirely to the supplied `staker_address`: [5](#0-4) 

There is no check that the caller is the staker, the staker's operational address, or any other authorized party. Any address can supply any valid `staker_address`.

### Impact Explanation
An attacker who is a delegator (or the staker themselves) in staker X's pool can call `update_rewards(staker_address=X)` in any block. The full block rewards are credited to staker X and its pool members. The legitimate block proposer Y, who should have received those rewards, is permanently locked out for that block because `last_reward_block` has already been advanced. This constitutes **theft of unclaimed yield** (High impact): the proposer's per-block STRK rewards are permanently lost to them and redirected to an attacker-chosen staker.

### Likelihood Explanation
The function is public with no access control. Any delegator or staker can execute this in every block. The attacker only needs to submit a transaction before the legitimate proposer's reward-claiming transaction lands. On Starknet, where sequencer ordering is observable, this is straightforward to execute repeatedly.

### Recommendation
Restrict `update_rewards` so that only the staker's registered operational address (or the staker address itself) can trigger it for a given `staker_address`. For example, assert that `get_caller_address()` equals `staker_info.operational_address` or `staker_address` before proceeding. This mirrors the fix recommended in the external report: validate the entity before using it in a critical accounting operation.

### Proof of Concept
1. Staker A (attacker) and Staker B (legitimate block proposer) are both registered.
2. In block N, Staker B is the proposer and intends to call `update_rewards(staker_address=B)`.
3. Attacker A calls `update_rewards(staker_address=A, disable_rewards=false)` in the same block, landing first.
4. `last_reward_block` is set to N; block rewards are credited to Staker A.
5. Staker B's call reverts with `REWARDS_ALREADY_UPDATED` because `current_block_number == last_reward_block`.
6. Staker B permanently loses their block reward for block N. Attacker A (and A's delegators) receive rewards they did not earn. [6](#0-5)

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
