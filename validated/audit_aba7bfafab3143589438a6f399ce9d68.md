### Title
Missing Caller Authorization in `update_rewards` Allows Any Address to Permanently Freeze All Staker Block Rewards - (File: `src/staking/staking.cairo`)

### Summary

The `update_rewards` function in `StakingRewardsManagerImpl` is callable by any address, despite the protocol specification explicitly restricting it to "Only starkware sequencer." Because `last_reward_block` is a **global** storage slot updated unconditionally before the `disable_rewards` guard, any unprivileged caller can invoke `update_rewards(..., disable_rewards: true)` each block to consume the block's reward slot without distributing any rewards, permanently preventing the sequencer from distributing block rewards for that block. Repeating this every block freezes all staker and delegator yield indefinitely.

---

### Finding Description

`IStakingRewardsManager::update_rewards` is the consensus-phase reward distribution entry point. The protocol specification states its access control is **"Only starkware sequencer"** (docs/spec.md line 1645). However, the implementation contains no such check. [1](#0-0) 

The function begins with `general_prerequisites()`, which only asserts the contract is not paused and the caller is non-zero: [2](#0-1) 

Critically, `last_reward_block` is written to storage **before** the `disable_rewards` branch is evaluated: [3](#0-2) 

`last_reward_block` is a single global `BlockNumber` field (not per-staker): [4](#0-3) 

The guard that prevents double-distribution for the same block is: [5](#0-4) 

Once any call to `update_rewards` succeeds for block `N`, every subsequent call for block `N` reverts with `REWARDS_ALREADY_UPDATED`. Because the write to `last_reward_block` happens unconditionally before the `disable_rewards` early-return, a call with `disable_rewards: true` consumes the slot and distributes nothing.

Compare with `update_rewards_from_attestation_contract`, which correctly enforces its caller restriction: [6](#0-5) 

No equivalent `assert_caller_is_sequencer` guard exists in `update_rewards`.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` at the start of every block:

1. Sets `last_reward_block` to the current block number.
2. Returns immediately without distributing any rewards (the `disable_rewards || self.is_pre_consensus()` branch).
3. Causes every subsequent sequencer call for that block to revert with `REWARDS_ALREADY_UPDATED`.

Block rewards for that block are permanently lost — there is no mechanism to retroactively distribute missed blocks. Repeating this attack every block freezes **all** staker and delegator block rewards for the entire consensus-rewards phase.

---

### Likelihood Explanation

**High.** The function is publicly callable with no role restriction. The attack requires only a valid staker address (readable from on-chain events) and a transaction per block. Gas cost is the only barrier. The attacker gains nothing financially but can permanently deny yield to all protocol participants.

---

### Recommendation

Add a sequencer-only access control check at the top of `update_rewards`, analogous to the existing `assert_caller_is_attestation_contract` pattern used in `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer(); // ADD THIS
    ...
}
```

Alternatively, move the `self.last_reward_block.write(current_block_number)` call to after the `disable_rewards` guard so that a no-op call does not consume the block's reward slot.

---

### Proof of Concept

```
// Attacker script (runs once per block, before the sequencer):
// 1. Read any active staker address from NewStaker events.
// 2. Call: staking_contract.update_rewards(staker_address, disable_rewards=true)
//    - general_prerequisites() passes (not paused, caller != 0)
//    - current_block > last_reward_block → passes
//    - last_reward_block := current_block  ← slot consumed
//    - disable_rewards == true → early return, zero rewards distributed
// 3. Sequencer calls: staking_contract.update_rewards(staker_address, disable_rewards=false)
//    - current_block == last_reward_block → REWARDS_ALREADY_UPDATED revert
// Result: No staker receives block rewards for this block.
// Repeat every block → all yield permanently frozen.
``` [7](#0-6) [8](#0-7)

### Citations

**File:** src/staking/staking.cairo (L186-187)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
```

**File:** src/staking/staking.cairo (L1398-1402)
```text
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
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

**File:** docs/spec.md (L1643-1646)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```
