### Title
Unprivileged Caller Can Permanently Freeze Consensus Rewards by Consuming the Global `last_reward_block` Slot with `disable_rewards: true` - (File: src/staking/staking.cairo)

---

### Summary

`IStakingRewardsManager::update_rewards` is callable by any non-zero address with no access control. It writes `last_reward_block` to the current block **before** checking the `disable_rewards` flag. An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` every block consumes the single per-block reward slot without distributing any rewards, permanently starving all stakers of consensus-phase yield.

---

### Finding Description

`update_rewards` in `src/staking/staking.cairo` enforces a global, single-slot rate limit via `last_reward_block`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only: not paused, caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    self.last_reward_block.write(current_block_number);   // slot consumed HERE

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // rewards skipped, slot already gone
    }
    ...
}
``` [1](#0-0) 

`general_prerequisites` imposes no role check — only "not paused" and "caller != zero address": [2](#0-1) 

The interface documents no access restriction either: [3](#0-2) 

Because `last_reward_block` is written unconditionally before the `disable_rewards` branch, any caller can:

1. Pick any currently active staker address (publicly readable from `stakers` vec or events).
2. Call `update_rewards(active_staker, disable_rewards: true)` once per block.
3. The slot is consumed; every subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
4. No rewards are ever distributed.

The `last_reward_block` field is **global** (not per-staker), so a single attacker call per block blocks reward distribution for the entire protocol. [4](#0-3) 

---

### Impact Explanation

This matches **"Permanent freezing of unclaimed yield"** (High). In the consensus-rewards phase, all staker and pool-member yield accrues exclusively through `update_rewards`. If the slot is consumed with `disable_rewards: true` every block, no staker ever accumulates new `unclaimed_rewards_own` and no pool ever receives rewards via `_update_rewards`. The yield is not merely delayed — it is permanently lost for every block the attacker acts, with no recovery path for the missed blocks.

---

### Likelihood Explanation

High. The attacker requires:
- A non-zero Starknet address (no stake, no role).
- One valid active staker address (trivially obtained from on-chain events or `get_stakers`).
- Gas to submit one transaction per block.

Starknet transaction fees are low. The attack is fully permissionless, requires no capital, and is sustainable indefinitely.

---

### Recommendation

1. **Restrict the caller**: Gate `update_rewards` to the attestation contract, a designated keeper role, or the staker/operational address itself. The function is already called internally by the attestation flow via `update_rewards_from_attestation_contract`; the public `update_rewards` entry point for the consensus phase should have an equivalent caller restriction.

2. **Move the slot write after the guard**: Write `last_reward_block` only when rewards are actually distributed (i.e., after the `disable_rewards` check), so a no-op call does not consume the slot.

3. **Make `last_reward_block` per-staker** if the intent is to allow independent per-staker reward updates.

---

### Proof of Concept

```
// Attacker is any EOA with a small STRK balance for gas.
// Consensus rewards phase is active (is_pre_consensus() == false).

loop every block:
    staking_contract.update_rewards(
        staker_address = <any active staker>,
        disable_rewards = true
    )
    // last_reward_block is now == current_block
    // No rewards distributed
    // Any legitimate update_rewards call in this block reverts with REWARDS_ALREADY_UPDATED
```

All stakers and pool members accumulate zero consensus rewards for every block the attacker sustains the call. The `unclaimed_rewards_own` field on every `InternalStakerInfoLatest` remains frozen at its pre-attack value indefinitely. [5](#0-4)

### Citations

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
