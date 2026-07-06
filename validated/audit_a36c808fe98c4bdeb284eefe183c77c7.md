### Title
Missing Access Control on `update_rewards` Allows Any Caller to Monopolize Block Rewards and Permanently Freeze Other Stakers' Yield - (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract is specified as callable only by the Starkware sequencer, but the implementation enforces no such restriction. Because `last_reward_block` is a single global storage slot, only one successful call to `update_rewards` is permitted per block. Any unprivileged user can call `update_rewards` for their own staker every block, consuming the per-block reward slot and permanently preventing the sequencer from distributing rewards to all other stakers.

---

### Finding Description

The protocol specification at `docs/spec.md` line 1645 states:

> **Access control:** Only starkware sequencer.

The implementation at `src/staking/staking.cairo` lines 1449–1507 enforces only three conditions:

1. Contract is not paused (`general_prerequisites()`)
2. `current_block_number > self.last_reward_block.read()` — one successful call per block, globally
3. The target staker exists, is active, and has non-zero balance [1](#0-0) 

There is no check that the caller is the authorized sequencer. The `last_reward_block` field is a single global `BlockNumber` value in storage, not a per-staker map: [2](#0-1) 

Once `update_rewards` succeeds for any staker in block N, the global `last_reward_block` is set to N: [3](#0-2) 

Any subsequent call in block N — including the sequencer's call for the legitimate block producer — reverts with `REWARDS_ALREADY_UPDATED`. The block rewards for that block are permanently lost for all other stakers.

Compare with `update_rewards_from_attestation_contract`, which correctly enforces its caller restriction: [4](#0-3) 

The spec's access control requirement is documented but not implemented: [5](#0-4) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield for all stakers except the attacker's.**

Block rewards in the consensus rewards phase are computed per block and distributed to exactly one staker per block. There is no accumulation mechanism: if the sequencer cannot call `update_rewards` for staker B in block N (because the attacker already called it for staker A), staker B's rewards for block N are permanently lost. An attacker who calls `update_rewards` for their own staker every block causes all other stakers to receive zero block rewards indefinitely.

---

### Likelihood Explanation

**High.** No privileged key, role, or special condition is required. Any address can call `update_rewards` with any valid staker address. The attack requires only one transaction per block, which is trivially sustainable on-chain.

---

### Recommendation

Add an access control check at the entry of `update_rewards` to restrict callers to the authorized sequencer address. This mirrors the pattern already used in `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.assert_caller_is_sequencer(); // <-- add this
    self.general_prerequisites();
    ...
}
```

A sequencer address should be stored in contract state and settable by a governance role, analogous to how `attestation_contract` is stored and checked.

---

### Proof of Concept

1. Attacker stakes the minimum amount, becoming `staker_A`.
2. Each block, the attacker calls `update_rewards(staker_A, false)`.
3. `staker_A` receives block rewards; `last_reward_block` is set to the current block number.
4. The sequencer attempts `update_rewards(block_producer, false)` in the same block → reverts with `REWARDS_ALREADY_UPDATED`.
5. The block producer and all other stakers receive zero rewards for that block.
6. Repeated every block, all other stakers are permanently frozen out of consensus block rewards. [6](#0-5) [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L187-187)
```text
        last_reward_block: BlockNumber,
```

**File:** src/staking/staking.cairo (L1394-1401)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

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

**File:** docs/spec.md (L1626-1653)
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
