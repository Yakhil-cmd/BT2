### Title
Unprivileged Caller Can Permanently Deny Consensus Block Rewards by Calling `update_rewards` with `disable_rewards: true` — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract has no caller access control and accepts a `disable_rewards` boolean parameter. Any unprivileged address can call `update_rewards(valid_staker_address, disable_rewards: true)` to consume the global per-block reward slot (`last_reward_block`) without distributing any rewards. Because `last_reward_block` is a single global storage variable, all subsequent legitimate calls to `update_rewards` in the same block revert with `REWARDS_ALREADY_UPDATED`. An attacker can repeat this every block, permanently denying all stakers their consensus block rewards at the cost of only gas.

---

### Finding Description

`update_rewards` is the consensus-phase reward distribution entry point. It enforces a global one-call-per-block invariant via `last_reward_block`:

```cairo
// src/staking/staking.cairo lines 1449–1485
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks pause flag
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker validity checks ...

    // Update last block rewards.
    self.last_reward_block.write(current_block_number);   // ← global slot consumed here

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← returns WITHOUT distributing rewards
    }
    // ... reward calculation and distribution ...
}
``` [1](#0-0) 

`general_prerequisites()` only checks the pause flag — there is no restriction on who may call `update_rewards` or pass `disable_rewards: true`. [2](#0-1) 

`last_reward_block` is a single global `BlockNumber` field, not per-staker: [3](#0-2) 

When `disable_rewards: true` is passed, the function writes `last_reward_block = current_block_number` and returns immediately, distributing nothing. Any subsequent call in the same block — including the legitimate sequencer/operator call with `disable_rewards: false` — hits the `REWARDS_ALREADY_UPDATED` assertion and reverts. The rewards for that block are permanently unrecoverable. [4](#0-3) 

This is structurally identical to the H-08 pattern: a publicly callable function with no ownership/caller check modifies shared state (here `last_reward_block`, there `executionHistory[nonce]`) in a way that permanently blocks a legitimate future operation.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Every block in which the attacker front-runs with `update_rewards(valid_staker, disable_rewards: true)`, the entire protocol's consensus block rewards for that block are permanently lost. No staker can recover those rewards because the per-block slot is already consumed. Sustained over many blocks, this drains all stakers and pool members of their expected yield.

---

### Likelihood Explanation

**High.** The attack requires no special privilege, no capital, and no protocol knowledge beyond knowing one valid active staker address (which is public on-chain). The only cost is Starknet gas per block, which is low. The attacker gains nothing financially (pure griefing), but the damage to stakers is real and irreversible.

---

### Recommendation

Restrict who may call `update_rewards` with `disable_rewards: true`. Options:

1. **Access-control the `disable_rewards` path**: require `only_operator` or a designated sequencer role when `disable_rewards: true`.
2. **Remove `disable_rewards` from the public interface**: make it an internal flag set only by privileged internal callers (e.g., `unstake_intent` flow).
3. **Separate the functions**: expose a public `update_rewards(staker_address)` (no flag) and a privileged `update_rewards_no_distribute(staker_address)` callable only by a trusted role.

---

### Proof of Concept

1. Attacker identifies any valid, active staker address `S` (readable from public events or `get_stakers()`).
2. Each block, attacker submits: `update_rewards(S, disable_rewards: true)`.
3. This writes `last_reward_block = current_block_number` and returns without distributing rewards.
4. The legitimate sequencer/operator call `update_rewards(S, disable_rewards: false)` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. All stakers and pool members permanently lose their consensus block rewards for that block.
6. Repeated every block, the attacker continuously freezes all protocol yield at minimal cost.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1490)
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

```
