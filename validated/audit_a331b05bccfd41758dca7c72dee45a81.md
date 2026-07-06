### Title
Unprivileged Caller Can Permanently Suppress All Block Rewards via `disable_rewards` Flag — (File: `src/staking/staking.cairo`)

---

### Summary

`update_rewards` in the Staking contract accepts a caller-controlled `disable_rewards: bool` parameter with no access control. Any unprivileged caller can invoke this function with `disable_rewards: true` every block, consuming the single global `last_reward_block` slot without distributing any rewards, permanently denying block rewards to every staker in the protocol.

---

### Finding Description

`update_rewards` is a public function gated only by `general_prerequisites()` (unpaused + non-zero caller): [1](#0-0) 

The function writes the current block number to the **global** `last_reward_block` before checking `disable_rewards`: [2](#0-1) 

`last_reward_block` is a single contract-wide value, not per-staker: [3](#0-2) 

The guard that prevents double-calling within the same block checks this global value: [4](#0-3) 

Because `last_reward_block` is written **before** the `disable_rewards` branch is evaluated, a caller who passes `disable_rewards: true` permanently consumes the reward slot for that block. No subsequent caller can distribute rewards for that block, because the guard will revert with `REWARDS_ALREADY_UPDATED`.

The `disable_rewards` path is reached by any caller — there is no role check, no staker-only restriction, and no whitelist. The only precondition is that `staker_address` refers to an active staker with non-zero balance, which is trivially satisfiable using any publicly visible staker address.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

When consensus rewards are active (`!is_pre_consensus()`), block rewards are the sole mechanism by which stakers accumulate `unclaimed_rewards_own` and pools accumulate their share. For every block where an attacker calls `update_rewards(any_valid_staker, disable_rewards: true)`:

1. `last_reward_block` is set to the current block.
2. The function returns without calling `_update_rewards`.
3. No staker receives any block reward for that block — ever.
4. The reward supplier's `unclaimed_rewards` is never incremented for that block.

The loss is permanent: there is no catch-up mechanism. Stakers and delegators lose all yield for every block the attacker targets. [5](#0-4) 

---

### Likelihood Explanation

**High.** The attack requires:
- No special role or privilege.
- No capital at risk.
- One transaction per block (automatable with a simple bot).
- Any valid staker address (readable from on-chain events).

The attacker has no profit motive but can inflict unbounded, permanent yield loss on all stakers and delegators at negligible cost.

---

### Recommendation

Remove `disable_rewards` as a caller-supplied parameter. If the protocol needs a "no-op" update path (e.g., to advance `last_reward_block` without distributing rewards during a transition), gate it behind a privileged role (e.g., `only_app_governor`) or derive the flag from on-chain state rather than accepting it from an untrusted caller.

```cairo
// Before (vulnerable):
fn update_rewards(ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool)

// After (safe):
fn update_rewards(ref self: ContractState, staker_address: ContractAddress)
// derive disable_rewards internally from protocol state only
```

---

### Proof of Concept

1. Consensus rewards are active (`consensus_rewards_first_epoch` has been set and the current epoch has passed it).
2. Attacker identifies any active staker `S` with non-zero STRK balance (readable from `NewStaker` events).
3. At the start of every block, attacker submits:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. The call succeeds: `last_reward_block` is updated to the current block, then the function returns early.
5. Any honest caller (staker, delegator, or keeper) who attempts `update_rewards` for the same block receives `REWARDS_ALREADY_UPDATED` and reverts.
6. All stakers and delegators receive zero block rewards for that block. Repeated every block, the entire consensus reward stream is permanently suppressed. [6](#0-5)

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
