### Title
`update_rewards()` Is Publicly Accessible — Missing Sequencer-Only Access Control - (File: `src/staking/staking.cairo`)

---

### Summary

`update_rewards()` in the Staking contract is documented to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can invoke it with `disable_rewards: true`, which advances the global `last_reward_block` without distributing any rewards. Because `last_reward_block` is a single contract-wide storage slot, one such call per block permanently prevents the legitimate sequencer from distributing rewards to all stakers.

---

### Finding Description

The spec for `update_rewards` explicitly states:

> **access control**: Only starkware sequencer. [1](#0-0) 

The implementation, however, performs no caller validation whatsoever:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks pause
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    self.last_reward_block.write(current_block_number);   // global slot updated
    if disable_rewards || self.is_pre_consensus() {
        return;                                           // exits without distributing
    }
    ...
}
``` [2](#0-1) 

`last_reward_block` is a single contract-wide storage variable (not per-staker). Writing it for any call blocks every subsequent call in the same block with `REWARDS_ALREADY_UPDATED`. [3](#0-2) 

Contrast this with `update_rewards_from_attestation_contract`, which correctly enforces its caller restriction:

```cairo
self.assert_caller_is_attestation_contract();
``` [4](#0-3) 

---

### Impact Explanation

An attacker calls `update_rewards(any_active_staker, disable_rewards: true)` at the start of every block:

1. `last_reward_block` is set to the current block number.
2. The function returns early — no rewards are computed or distributed.
3. The legitimate sequencer's call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
4. Repeated every block → **all stakers and delegators permanently receive zero block rewards**.

This constitutes **permanent freezing of unclaimed yield** for the entire protocol.

**Allowed impact matched**: *High — Permanent freezing of unclaimed yield or unclaimed royalties.*

---

### Likelihood Explanation

- The entry point is a public, permissionless external function.
- No funds, stake, or special role are required to call it.
- The attack costs only gas per block and requires no coordination.
- An adversary motivated to harm the protocol (e.g., a competing validator set or griefing actor) can sustain this indefinitely.

---

### Recommendation

Add a sequencer-only caller check at the top of `update_rewards`, analogous to the existing `assert_caller_is_attestation_contract` pattern used in `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer();   // <-- add this
    ...
}
```

The check should verify `get_caller_address() == sequencer_address` where `sequencer_address` is stored at construction time, mirroring how `attestation_contract` is stored and checked.

---

### Proof of Concept

```
// Attacker script — run once per block before the sequencer tx:
// 1. Pick any active staker address (publicly readable from events).
// 2. Call update_rewards(staker_address, disable_rewards: true).
//    → last_reward_block := current_block_number
//    → returns without distributing rewards
// 3. Sequencer's update_rewards call in the same block:
//    → assert!(current_block_number > last_reward_block) FAILS
//    → reverts with REWARDS_ALREADY_UPDATED
// 4. No staker or delegator accumulates unclaimed_rewards_own for this block.
// 5. Repeat every block → zero yield distributed protocol-wide.
``` [5](#0-4)

### Citations

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1399-1401)
```text
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
