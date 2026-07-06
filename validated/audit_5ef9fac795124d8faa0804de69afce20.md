### Title
Missing Caller Authorization on `update_rewards` Allows Any Address to Permanently Freeze Staker Block Rewards — (`src/staking/staking.cairo`)

---

### Summary

`IStakingRewardsManager::update_rewards` is specified to be callable "Only starkware sequencer" but the implementation contains **no caller check**. Any unprivileged address can call it with `disable_rewards: true`, consuming the single per-block reward slot (guarded by the global `last_reward_block`) and permanently discarding that block's rewards for all stakers.

---

### Finding Description

The protocol specification is explicit:

> **access control**: Only starkware sequencer. [1](#0-0) 

The implementation of `update_rewards` in `StakingRewardsManagerImpl` begins with only `self.general_prerequisites()` (a pause check) and a block-number guard. There is no `assert_caller_is_sequencer`, no role check, and no `only_operator` modifier of any kind: [2](#0-1) 

The function then unconditionally writes the current block number into the **global** `last_reward_block` storage slot before the `disable_rewards` branch: [3](#0-2) 

`last_reward_block` is a single contract-wide value, not per-staker: [4](#0-3) 

Because the guard is `current_block_number > self.last_reward_block.read()`, only **one** successful call to `update_rewards` is possible per block. Once that slot is consumed — by anyone — every subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`.

---

### Impact Explanation

An attacker calls `update_rewards(staker_address: <any_valid_active_staker>, disable_rewards: true)` at the start of every block. This:

1. Passes all validation (staker exists, has non-zero balance, block is new).
2. Writes `current_block_number` into `last_reward_block`.
3. Returns immediately without distributing any rewards (because `disable_rewards == true`).

The sequencer's legitimate call in the same block then reverts with `REWARDS_ALREADY_UPDATED`. The block's rewards are **permanently lost** — there is no catch-up mechanism; `last_reward_block` is never rolled back and missed blocks are not replayed. Repeated across every block, this permanently freezes all unclaimed yield for all stakers and their delegators.

This matches: **High — Permanent freezing of unclaimed yield.**

---

### Likelihood Explanation

`update_rewards` is a public, permissionless entry point on a deployed contract. No special token balance, role, or privileged access is required. The only prerequisite is supplying any valid, active staker address (trivially obtained from on-chain events). The attacker pays only gas. The attack is sustainable indefinitely.

---

### Recommendation

Add a sequencer-only caller check at the top of `update_rewards`, analogous to the existing pattern used in `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
+   self.assert_caller_is_sequencer(); // enforce "Only starkware sequencer"
    ...
}
```

The check should verify `get_caller_address() == <configured_sequencer_address>`, stored and settable by governance, mirroring how `attestation_contract` is stored and checked: [5](#0-4) 

---

### Proof of Concept

```
// Any EOA or contract can execute this every block:
// 1. Pick any staker_address that is active (non-zero balance, not in exit window).
// 2. Call update_rewards with disable_rewards = true.
//    - Passes: current_block > last_reward_block  (first call this block)
//    - Passes: staker exists and is active
//    - Writes: last_reward_block = current_block_number
//    - Returns: early (disable_rewards == true), zero rewards distributed
// 3. Sequencer's own update_rewards call now reverts: REWARDS_ALREADY_UPDATED.
// 4. Repeat next block.
//
// Result: last_reward_block advances every block but no rewards are ever
//         credited to staker.unclaimed_rewards_own or transferred to pools.
//         All staker and delegator yield is permanently frozen.
``` [6](#0-5) [7](#0-6)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L141-143)
```text
        /// The contract that staker sends attestation transaction to.
        attestation_contract: ContractAddress,
        /// Map version to class hash of the contract.
```

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
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
