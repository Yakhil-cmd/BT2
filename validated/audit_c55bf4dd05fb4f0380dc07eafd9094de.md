### Title
Unprivileged Caller Can Permanently Freeze All Staker Block Rewards via `disable_rewards` Flag in `update_rewards` - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the Staking contract accepts a `disable_rewards: bool` flag from any unprivileged caller. When called with `disable_rewards: true`, it advances the global `last_reward_block` checkpoint without distributing any rewards, permanently blocking legitimate reward distribution for that block for all stakers.

### Finding Description
The `update_rewards` function is publicly callable with no access control beyond the general pause/non-zero-caller check. It accepts a `disable_rewards` flag that, when `true`, causes the function to:

1. Pass all staker validity checks (lines 1460–1482)
2. Advance the global `last_reward_block` to the current block (line 1485)
3. Return early without distributing any rewards (lines 1487–1489) [1](#0-0) 

The function enforces a strict one-call-per-block invariant via:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [2](#0-1) 

Because `last_reward_block` is a **single global variable** (not per-staker), any call that advances it — including one with `disable_rewards: true` — permanently consumes that block's reward slot for every staker in the protocol. [3](#0-2) 

The `general_prerequisites()` guard only checks pause state and non-zero caller — no role or privileged-caller check exists: [4](#0-3) 

The `disable_rewards` flag is the direct analog to the external report's "optional behavior flag" pattern: a single boolean that silently suppresses a critical protocol action (reward distribution) while still advancing shared state (`last_reward_block`), creating an exploitable interaction.

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` once per block in consensus mode permanently destroys all block rewards for that block across the entire protocol. Repeated across every block, this freezes 100% of consensus-mode staking yield for all stakers indefinitely. The rewards are not deferred — they are simply never computed or credited, and the block slot cannot be reclaimed.

### Likelihood Explanation
**High.** The function is permissionlessly callable by any non-zero address. There is no economic cost to the attacker beyond gas. The attack requires no special knowledge, no privileged key, and no coordination. A single bot monitoring for new blocks and calling `update_rewards` with `disable_rewards: true` is sufficient to execute the attack continuously.

### Recommendation
Remove the `disable_rewards` parameter from the public interface entirely, or restrict `update_rewards` to a trusted caller (e.g., the attestation contract or a designated operator role). If the `disable_rewards` path is needed for migration or emergency purposes, gate it behind an appropriate role check (e.g., `only_security_agent()` or `only_app_governor()`). The global `last_reward_block` advancement must never be reachable by an unprivileged caller with a flag that suppresses reward distribution.

### Proof of Concept

**Setup:** Protocol is in consensus mode (`consensus_rewards_first_epoch` has been set and passed).

**Attack steps:**

1. Attacker identifies any currently active, migrated staker (`staker_address`) with non-zero STRK balance.
2. At the start of each new block, attacker calls:
   ```
   staking.update_rewards(staker_address, disable_rewards: true)
   ```
3. Inside `update_rewards`:
   - All validity checks pass (staker is active, balance is non-zero).
   - `last_reward_block` is written to `current_block_number` (line 1485).
   - The `disable_rewards || self.is_pre_consensus()` branch is taken (line 1487), returning early with zero rewards distributed.
4. Any subsequent legitimate call to `update_rewards` in the same block (e.g., from the consensus reward pipeline) hits:
   ```
   assert!(current_block_number > self.last_reward_block.read(), ...)
   ```
   and reverts with `REWARDS_ALREADY_UPDATED`.
5. Block rewards for that block are permanently lost for all stakers.
6. Repeating this every block freezes all consensus-mode staking yield indefinitely. [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L1187-1188)
```text
            let to_staker_info = self.internal_staker_info(staker_address: to_staker);

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
