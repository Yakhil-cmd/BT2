### Title
Missing Caller Access Control on `update_rewards` Allows Any Staker to Steal Block Rewards - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in `StakingRewardsManagerImpl` is documented to be callable only by the Starkware sequencer, but the implementation contains no such check. Any staker can call it for themselves at any block, claiming block rewards that should belong to the legitimate block producer, while simultaneously blocking the sequencer's intended call for that block via the global `last_reward_block` guard.

### Finding Description

The specification at `docs/spec.md:1644–1645` states:

> **access control**: Only starkware sequencer.

The implementation at `src/staking/staking.cairo:1447–1507` enforces no such restriction. The only gate is `general_prerequisites()`, which checks only that the contract is unpaused and the caller is non-zero:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [1](#0-0) 

The full `update_rewards` body has no `get_caller_address() == sequencer` assertion:

```cairo
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
    ...
    self.last_reward_block.write(current_block_number);
    ...
    self._update_rewards(...);
}
``` [2](#0-1) 

The `last_reward_block` is a **global** (not per-staker) storage variable. Once any call to `update_rewards` succeeds at block N, every subsequent call at block N reverts with `REWARDS_ALREADY_UPDATED`. This means only one staker can receive block rewards per block.

The interface definition confirms the function is public with no role annotation:

```cairo
pub trait IStakingRewardsManager<TContractState> {
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
``` [3](#0-2) 

### Impact Explanation

An attacker who holds the minimum stake can call `update_rewards(attacker_staker_address, false)` at every block. Because `last_reward_block` is global, the sequencer's intended call for the legitimate block producer at the same block will revert. The attacker receives rewards proportional to their stake; the legitimate block producer receives zero rewards for that block. Repeated across many blocks, this constitutes continuous theft of unclaimed yield from all other stakers who produce blocks.

This maps directly to the **High** impact category: *Theft of unclaimed yield*.

### Likelihood Explanation

Any registered staker (minimum stake required, no other privilege) can execute this attack. The entry path is a public ABI function with no role check. The attacker only needs to submit a transaction calling `update_rewards` with their own staker address before the sequencer's call lands in the same block. Because the sequencer on Starknet controls ordering, the attacker cannot guarantee front-running every block, but they can exploit any block where the sequencer does not call `update_rewards` first, or where the sequencer omits the call entirely (e.g., when the block producer is not a registered staker).

### Recommendation

Add an explicit caller check inside `update_rewards` to enforce the documented access control:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    ...
}
```

Alternatively, restrict the `IStakingRewardsManager` interface so that `update_rewards` is only callable via an internal/privileged path, consistent with the spec.

### Proof of Concept

1. Alice stakes the minimum amount and waits K epochs for her stake to become effective.
2. At block N (after consensus rewards start), Alice calls `update_rewards(alice_address, false)` directly.
3. `last_reward_block` is set to N; Alice's `unclaimed_rewards_own` is incremented by `(alice_stake / total_stake) * block_rewards`.
4. The sequencer attempts to call `update_rewards(legitimate_producer_address, false)` at block N — it reverts with `REWARDS_ALREADY_UPDATED`.
5. Alice repeats at every block. The legitimate block producers accumulate zero rewards while Alice continuously siphons block rewards proportional to her stake. [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** src/staking/interface.cairo (L303-311)
```text
#[starknet::interface]
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
