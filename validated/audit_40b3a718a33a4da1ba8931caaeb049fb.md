### Title
Unrestricted `update_rewards` Allows Any Staker to Steal Block Rewards from Legitimate Block Producers - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in the Staking contract has no access control. Combined with a global `last_reward_block` lock that allows only one reward distribution per block, any registered staker can call `update_rewards` for themselves and claim 100% of block rewards — stealing yield that should go to the legitimate block producer.

### Finding Description

`update_rewards` is the V3 consensus-rewards entry point. Its only gate is `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero: [1](#0-0) 

The global `last_reward_block` storage variable is written on every successful call, preventing a second call in the same block: [2](#0-1) 

When rewards are distributed, `strk_total_stake` is set to the **calling staker's own balance**, not the protocol-wide total stake: [3](#0-2) 

Inside `_update_rewards → calculate_staker_own_rewards`, the reward formula is:

```
staker_reward = block_rewards × (own_balance / strk_total_stake)
             = block_rewards × (own_balance / own_balance)
             = block_rewards × 1  →  100% of block rewards
``` [4](#0-3) 

There is no check that the `staker_address` argument is the actual block producer for the current block, and no privileged role is required to call the function: [5](#0-4) 

### Impact Explanation

Any registered staker (minimum stake only) can call `update_rewards(attacker_address, false)` once per block. Because `last_reward_block` is a global lock, the first caller per block wins 100% of that block's STRK rewards. Legitimate block producers who call later in the same block receive `REWARDS_ALREADY_UPDATED` and earn nothing. Over many blocks, the attacker accumulates rewards in `unclaimed_rewards_own` and drains them via `claim_rewards`. This is **theft of unclaimed yield** — a High-severity impact under the allowed scope. [6](#0-5) 

### Likelihood Explanation

The attack requires only a valid staker registration (stake ≥ `min_stake`) and the ability to submit a transaction before the consensus layer's own `update_rewards` call lands. On Starknet, transaction ordering is controlled by the sequencer, but the function is fully public and callable by any EOA or contract. Any epoch in which the attacker's transaction is sequenced first results in stolen rewards. The cost is a single `stake()` call plus gas per block.

### Recommendation

Add an access-control check to `update_rewards` so that only the designated consensus/sequencer role (or the attestation contract) may call it. For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.roles.only_app_governor(); // or a dedicated CONSENSUS_LAYER role
    ...
}
```

Alternatively, derive `staker_address` from a verifiable on-chain signal (e.g., the block proposer field) rather than accepting it as a caller-supplied argument.

### Proof of Concept

1. Eve calls `stake(reward_address: eve, operational_address: eve_op, amount: min_stake)` — she is now a registered staker.
2. Consensus rewards are active (`consensus_rewards_first_epoch` has passed).
3. At the start of every new block, Eve submits `update_rewards(staker_address: eve, disable_rewards: false)`.
4. Because `current_block_number > last_reward_block`, the call succeeds; `last_reward_block` is set to the current block.
5. `calculate_block_rewards` returns the full STRK block reward; `strk_total_stake = eve's own balance`; Eve receives 100% of the block reward added to `unclaimed_rewards_own`.
6. The legitimate block producer calls `update_rewards` later in the same block → reverts with `REWARDS_ALREADY_UPDATED`.
7. Eve calls `claim_rewards(eve)` to transfer accumulated stolen rewards to her reward address. [7](#0-6) [8](#0-7)

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

**File:** src/staking/staking.cairo (L2349-2376)
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

**File:** src/staking/interface.cairo (L304-311)
```text
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```
