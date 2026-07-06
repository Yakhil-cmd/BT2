### Title
Unprivileged Caller Can Permanently Suppress Block Rewards by Calling `update_rewards` with `disable_rewards: true` — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in `staking.cairo` is publicly callable by any non-zero address. It unconditionally advances the global `last_reward_block` accounting variable before checking the `disable_rewards` flag. When any caller passes `disable_rewards: true`, the block's reward slot is permanently consumed without distributing rewards to any staker. Because `last_reward_block` is a single global variable, one such call per block is sufficient to freeze all staker yield for that block forever.

---

### Finding Description

`update_rewards` is defined in `StakingRewardsManagerImpl` with no role-based access control:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();   // only checks: unpaused + caller != zero
``` [1](#0-0) 

`general_prerequisites` enforces only two conditions — the contract is not paused and the caller is non-zero — with no privileged-role check: [2](#0-1) 

The function then unconditionally writes the current block number into the **global** `last_reward_block` storage slot:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [3](#0-2) 

`last_reward_block` is a single, non-per-staker storage variable: [4](#0-3) 

The guard at the top of the function enforces that only one successful call is possible per block:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [5](#0-4) 

**Root cause (accounting bug):** `last_reward_block` is updated (the block is "consumed") before the early-return guard on `disable_rewards` is evaluated. Any caller can therefore advance the accounting variable without triggering the corresponding reward distribution, permanently discarding that block's rewards. This is structurally identical to the reported Stargate bug: a state variable that tracks "processed" work is updated, but the matching value transfer is skipped.

---

### Impact Explanation

- An attacker calls `update_rewards(any_valid_staker, disable_rewards: true)` once per block.
- `last_reward_block` is set to the current block; all subsequent calls in the same block revert with `REWARDS_ALREADY_UPDATED`.
- No staker receives block rewards for that block; the yield is permanently lost and unrecoverable.
- Sustained over many blocks, this constitutes **permanent freezing of unclaimed yield** for the entire protocol.

This matches the allowed impact: *Permanent freezing of unclaimed yield or unclaimed royalties.*

---

### Likelihood Explanation

**High.** The function is permissionlessly callable by any externally-owned account. The attack requires only gas and can be automated to fire on every block. There is no economic barrier, no slashing risk, and no privileged credential required.

---

### Recommendation

Restrict who may supply `disable_rewards: true`. Options include:

1. **Access control gate**: require the caller to hold a specific role (e.g., `REWARDS_MANAGER_ROLE`) before the `disable_rewards` path is honoured.
2. **Separate the accounting update**: only advance `last_reward_block` after the reward-distribution path has been executed (or after a privileged caller has explicitly authorised the skip), mirroring the Stargate fix of updating the accounting variable in the same code path as the value transfer.

---

### Proof of Concept

1. Attacker (any non-zero EOA) calls `update_rewards(valid_staker, disable_rewards: true)` at block `N`.
2. `general_prerequisites()` passes (contract unpaused, caller non-zero).
3. Assert `N > last_reward_block` passes (first call this block).
4. `last_reward_block` is written to `N`.
5. `if disable_rewards` → `return` — no rewards distributed.
6. Any legitimate call to `update_rewards` at block `N` now reverts with `REWARDS_ALREADY_UPDATED`.
7. Block `N`'s rewards are permanently lost.
8. Repeat every block to freeze all consensus-phase staker yield indefinitely. [6](#0-5)

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
