### Title
Misplaced `last_reward_block` State Update Allows Griefing to Permanently Freeze Staker Block Rewards - (File: src/staking/staking.cairo)

### Summary

In `update_rewards`, the global `last_reward_block` storage write occurs in the "common" section of the function — before the `disable_rewards` branch check. Because `update_rewards` has no caller access control beyond `general_prerequisites()` (not-paused + non-zero caller), any unprivileged address can call it with `disable_rewards: true` for any valid staker, permanently consuming the one-call-per-block slot without distributing rewards. The legitimate consensus mechanism is then blocked from calling `update_rewards` for that block with `disable_rewards: false`.

### Finding Description

`update_rewards` in `src/staking/staking.cairo` is structured as follows:

1. **Common section** (runs unconditionally):
   - Checks `current_block_number > last_reward_block` (prevents double-processing)
   - Validates staker exists, is active, and has non-zero STRK balance
   - **Writes `last_reward_block = current_block_number`** ← misplaced state change

2. **Context-specific section** (only when rewards should be distributed):
   - `if disable_rewards || self.is_pre_consensus() { return; }`
   - Calculates and distributes block rewards [1](#0-0) 

The critical lines:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // ← line ~1485, common section

if disable_rewards || self.is_pre_consensus() {
    return;                                            // ← line ~1487, context-specific
}
``` [2](#0-1) 

The `last_reward_block` write should only occur when rewards are actually being processed (i.e., in the `disable_rewards = false` branch), but it is placed before the branch, in the common section. The function's only access guard is `general_prerequisites()`:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [3](#0-2) 

There is no role check, no staker-ownership check, and no check that the caller is the consensus/attestation contract.

### Impact Explanation

`last_reward_block` is a **single global variable** shared across all stakers and all blocks:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [4](#0-3) 

When an attacker calls `update_rewards(valid_staker, disable_rewards: true)` for block N:
- `last_reward_block` is set to N
- No rewards are distributed
- Any subsequent call to `update_rewards` for block N (by the legitimate consensus mechanism with `disable_rewards: false`) fails with `REWARDS_ALREADY_UPDATED`

The block producer permanently loses their block rewards for block N. This maps directly to **High: Permanent freezing of unclaimed yield**.

### Likelihood Explanation

- `update_rewards` is a public function with no privileged-caller restriction — any non-zero address can call it.
- The attacker only needs to supply any currently-active staker address with non-zero STRK balance (public on-chain information).
- The attacker must front-run the consensus mechanism's call for each target block. On Starknet L2, transaction ordering within a block is observable, making front-running feasible.
- The attack costs only gas and can be repeated every block to continuously deny rewards to one or all block producers.

### Recommendation

Move `self.last_reward_block.write(current_block_number)` to after the `disable_rewards` guard, so it only executes when rewards are actually being distributed:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}

// Only mark the block as reward-processed when rewards are actually distributed.
self.last_reward_block.write(current_block_number);

// Get current block data and update rewards.
...
```

Alternatively, add an access-control check (e.g., `assert_caller_is_attestation_contract()` or a dedicated `REWARDS_MANAGER` role) to restrict who may call `update_rewards`.

### Proof of Concept

1. Staker `S` is the block producer for block N. They are active and have non-zero STRK balance.
2. Attacker observes block N being produced and submits (with higher gas priority):
   ```
   staking_contract.update_rewards(staker_address: S, disable_rewards: true)
   ```
3. Transaction executes:
   - `current_block_number (N) > last_reward_block` → passes
   - Staker S is active with non-zero balance → passes
   - `last_reward_block.write(N)` → **block N consumed**
   - `disable_rewards == true` → returns early, no rewards distributed
4. Consensus mechanism submits:
   ```
   staking_contract.update_rewards(staker_address: S, disable_rewards: false)
   ```
5. Transaction fails: `current_block_number (N) > last_reward_block (N)` → `N > N` is false → `REWARDS_ALREADY_UPDATED` panic.
6. Staker S receives zero rewards for block N. The attacker repeats this every block. [1](#0-0)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
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
