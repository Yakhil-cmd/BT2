### Title
Missing Access Control on `update_rewards` Allows Anyone to Permanently Freeze Staker Rewards - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the staking contract is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can call `update_rewards(staker_address, disable_rewards: true)` to consume the per-block reward slot without distributing rewards, permanently blocking the legitimate sequencer from distributing consensus rewards for that block.

### Finding Description

The spec for `update_rewards` explicitly states:

> **access control**: Only starkware sequencer. [1](#0-0) 

However, the implementation in `StakingRewardsManagerImpl::update_rewards` performs no caller identity check whatsoever: [2](#0-1) 

The function only checks that the contract is unpaused and that `current_block_number > self.last_reward_block.read()`. It then unconditionally writes the current block number to `last_reward_block` before checking `disable_rewards`: [3](#0-2) 

`last_reward_block` is a **single global storage variable** (not a per-staker map). Writing it for any staker call blocks all subsequent calls in the same block:

```
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

An attacker who calls `update_rewards(any_staker_address, disable_rewards: true)` at the start of every block will:
1. Update `last_reward_block` to the current block number.
2. Return early without distributing any rewards (the `disable_rewards || self.is_pre_consensus()` branch).
3. Cause every subsequent sequencer call in that block to revert with `REWARDS_ALREADY_UPDATED`. [4](#0-3) 

### Impact Explanation

All stakers lose their consensus block rewards for every block in which the attacker front-runs the sequencer. Because the attack can be repeated every block at negligible cost, this constitutes **permanent freezing of unclaimed yield** for all active stakers.

This matches the allowed impact: **High — Permanent freezing of unclaimed yield or unclaimed royalties**.

### Likelihood Explanation

**High.** The function is publicly callable with no access restriction. Any address can call it. The attacker only needs to submit a transaction before the sequencer's `update_rewards` call each block. There is no economic barrier and no special privilege required.

### Recommendation

Add a sequencer-only access control guard at the top of `update_rewards`, consistent with the specification. For example:

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
    // ... rest of function
}
```

Alternatively, if the sequencer address is not stored on-chain, use Starknet's `get_sequencer_address()` syscall for the check.

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. Attacker monitors the mempool/block production.
3. At the start of block N, attacker calls:
   ```
   update_rewards(staker_address: any_valid_staker, disable_rewards: true)
   ```
4. `last_reward_block` is written to block N; no rewards are distributed.
5. The sequencer's legitimate call to `update_rewards(..., disable_rewards: false)` for any staker in block N reverts with `REWARDS_ALREADY_UPDATED`.
6. Stakers receive zero rewards for block N.
7. Attacker repeats step 3 every block — all stakers are permanently denied consensus rewards. [5](#0-4) [6](#0-5)

### Citations

**File:** docs/spec.md (L1626-1652)
```markdown
### update_rewards
```rust
fn update_rewards(ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool);
```
#### description <!-- omit from toc -->
Calculate and update the current block rewards for the for the given `staker_address`.
Send pool rewards to the pools.
Distribute rewards only if `disable_rewards` is False and consensus rewards already started.
#### emits <!-- omit from toc -->
1. [Staker Rewards Updated](#staker-rewards-updated)
2. [Rewards Supplied To Delegation Pool](#rewards-supplied-to-delegation-pool)
#### errors <!-- omit from toc -->
1. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
2. [REWARDS\_ALREADY\_UPDATED](#rewards_already_updated)
3. [STAKER\_NOT\_EXISTS](#staker_not_exists)
4. [INVALID\_STAKER](#invalid_staker)
#### pre-condition <!-- omit from toc -->
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
1. Calculate total block rewards.
2. Calculate staker rewards (include commission) and pool rewards.
3. Update `unclaimed_rewards_own` of the staker.
4. Update and transfer rewards to the pools, if exist.
5. Update Reward Supplier's `unclaimed_rewards`.
6. Update `last_reward_block` to the current block.
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
