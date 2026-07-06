### Title
Permissionless `update_rewards` with attacker-controlled `disable_rewards` allows permanent freezing of staker consensus rewards — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the staking contract is callable by any address and accepts a caller-controlled `disable_rewards` boolean. The function writes the global `last_reward_block` storage variable **before** checking whether rewards should actually be distributed. When `disable_rewards: true` is passed, the function returns early after consuming the block slot. Because `last_reward_block` is a single global variable checked at the top of every `update_rewards` call, an attacker can call `update_rewards(any_active_staker, disable_rewards: true)` once per block to permanently prevent all stakers from receiving consensus-period rewards.

---

### Finding Description

In `src/staking/staking.cairo`, the `update_rewards` function (part of `StakingRewardsManagerImpl`) performs the following sequence:

1. Calls `general_prerequisites()` — only checks the pause flag, no caller restriction.
2. Asserts `current_block_number > self.last_reward_block.read()` — enforces one call per block globally.
3. Validates the staker exists and is active.
4. **Writes `self.last_reward_block.write(current_block_number)`** — commits the block slot.
5. Checks `if disable_rewards || self.is_pre_consensus() { return; }` — returns early without distributing rewards. [1](#0-0) 

The critical ordering flaw is that `last_reward_block` is committed at step 4 **before** the early-return guard at step 5. This mirrors the MakerDAO analog exactly: state is marked "done" before the effect is applied, and the effect can be silently skipped.

Because there is no access-control check on `update_rewards` (no `CALLER_IS_NOT_*` error in the spec, and unit tests invoke it without any role setup), any address can call it. The `disable_rewards` parameter is fully attacker-controlled. [2](#0-1) 

---

### Impact Explanation

**HIGH — Permanent freezing of unclaimed yield.**

During the consensus rewards period (V3), `update_rewards` is the sole mechanism for distributing per-block rewards to stakers. If an attacker calls `update_rewards(any_active_staker, disable_rewards: true)` once per block:

- `last_reward_block` is advanced to the current block with zero rewards distributed.
- Every legitimate call to `update_rewards` in that block fails with `REWARDS_ALREADY_UPDATED`.
- The attacker repeats this every block at the cost of a single cheap Starknet transaction per block.
- All stakers and delegators are permanently denied consensus rewards.

The `last_reward_block` variable is global (not per-staker), so a single attacker call blocks reward distribution for **all** stakers simultaneously. [3](#0-2) 

---

### Likelihood Explanation

**High.** The entry path requires no privilege, no leaked key, and no external dependency. Any Starknet address can call `update_rewards` with an arbitrary active staker address and `disable_rewards: true`. The attacker needs only to know one active staker address (publicly observable on-chain) and submit one transaction per block. The cost is minimal on Starknet.

---

### Recommendation

**Short term:** Add access control to `update_rewards` so only an authorized caller (e.g., a designated consensus rewards operator or the attestation contract) can invoke it.

**Long term:** Move `self.last_reward_block.write(current_block_number)` to **after** the `disable_rewards` guard, so the block slot is only consumed when rewards are actually distributed:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
self.last_reward_block.write(current_block_number); // moved here
// ... reward calculation and distribution
```

This ensures the global state is only committed when the intended effect (reward distribution) actually occurs — directly addressing the root cause analog to the MakerDAO spell vulnerability.

---

### Proof of Concept

1. Consensus rewards period is active (`is_pre_consensus()` returns false).
2. Attacker identifies any active staker address `S` (publicly visible on-chain).
3. Each block, attacker submits: `staking.update_rewards(staker_address: S, disable_rewards: true)`.
4. `last_reward_block` is written to the current block number; function returns early — no rewards distributed.
5. The legitimate per-block call `staking.update_rewards(staker_address: S, disable_rewards: false)` reverts with `REWARDS_ALREADY_UPDATED`.
6. Repeated every block: all stakers accumulate zero `unclaimed_rewards_own` indefinitely.
7. Delegators' pool balances also receive no reward transfers from `send_rewards_to_delegation_pool`. [4](#0-3) [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L1449-1500)
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
```

**File:** src/staking/staking.cairo (L1611-1629)
```text
        /// Sends the rewards to `staker_address`'s reward address.
        /// Important note:
        /// After calling this function, one must write the updated staker_info to the storage.
        fn send_rewards_to_staker(
            ref self: ContractState,
            staker_address: ContractAddress,
            ref staker_info: InternalStakerInfoLatest,
            token_dispatcher: IERC20Dispatcher,
        ) {
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();

            self.emit(Events::StakerRewardClaimed { staker_address, reward_address, amount });
        }
```
