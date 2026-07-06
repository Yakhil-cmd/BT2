### Title
Missing Sequencer Access Control on `update_rewards` Allows Any Caller to Permanently Block Reward Distribution - (File: src/staking/staking.cairo)

### Summary

`StakingRewardsManagerImpl::update_rewards` is specified as "Only starkware sequencer" but the implementation contains no such check. Any non-zero address can call it with `disable_rewards: true`, which writes `last_reward_block` to the current block number without distributing any rewards. The sequencer's legitimate call for the same block then reverts with `REWARDS_ALREADY_UPDATED`, permanently destroying that block's consensus rewards for all stakers and delegators.

### Finding Description

The spec for `update_rewards` explicitly states:

> **access control**: Only starkware sequencer.

However, the implementation only calls `general_prerequisites()`, which checks:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
```

No sequencer identity check exists anywhere in `update_rewards`. The full function body is:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only: not paused, not zero caller
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker validity checks ...
    self.last_reward_block.write(current_block_number);   // ← state written unconditionally
    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← returns without distributing
    }
    // ... reward distribution ...
}
```

The critical sequence is:
1. `last_reward_block` is written to `current_block_number` at line 1485 **before** the `disable_rewards` guard at line 1487.
2. When `disable_rewards: true`, the function returns immediately after writing the block number, distributing zero rewards.
3. Any subsequent call in the same block (including the legitimate sequencer call) reverts with `REWARDS_ALREADY_UPDATED`.

This is structurally identical to the reported `trackUnseenRewards` pattern: a publicly callable function updates a timing/gating state variable (`last_reward_block` ≈ `lastUpdateTime`) without first completing the reward accounting, causing the legitimate reward distribution path to be permanently skipped for that block.

### Impact Explanation

**Impact: High.** Every block in which an attacker front-runs the sequencer, all stakers and their delegators receive zero consensus block rewards. Because the attack costs only gas and can be repeated every block, an attacker can permanently freeze the entire consensus reward stream. Stakers and pool members lose all unclaimed yield that would have accrued under the V3 consensus reward mechanism. The `block_rewards` and `cumulative_rewards_trace` in the pool contract are never updated for those blocks, so the loss is irrecoverable.

### Likelihood Explanation

**Likelihood: High.** The entry point is fully public (any non-zero address), requires no tokens, no stake, and no special role. The attacker only needs to submit a transaction before the sequencer's `update_rewards` call in each block. On Starknet, where the sequencer processes transactions in order, a determined attacker can reliably front-run this call every block at negligible cost.

### Recommendation

Add an explicit sequencer identity check at the top of `update_rewards`, consistent with the spec:

```cairo
fn update_rewards(...) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    // ...
}
```

Alternatively, move the `last_reward_block.write(current_block_number)` to **after** the reward distribution logic so that a call with `disable_rewards: true` does not consume the block's reward slot.

### Proof of Concept

```
// Scenario: consensus rewards are active, staker has non-zero balance.
// Block N begins.

// Step 1: Attacker (any address) calls update_rewards with disable_rewards=true.
//   → last_reward_block is written to block N.
//   → No rewards distributed.

// Step 2: Sequencer calls update_rewards(staker, disable_rewards=false) for block N.
//   → assert!(current_block_number > last_reward_block) FAILS.
//   → Reverts with REWARDS_ALREADY_UPDATED.
//   → Staker and all pool members receive zero rewards for block N.

// Attacker repeats every block → all consensus rewards permanently frozen.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L1447-1508)
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
