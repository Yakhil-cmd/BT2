### Title
Missing validation between `disable_rewards` flag and `last_reward_block` update allows any caller to permanently freeze per-block staker rewards — (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the `Staking` contract is callable by any unprivileged address. It unconditionally writes `last_reward_block` to the current block **before** checking the caller-supplied `disable_rewards` flag. When an attacker calls the function with `disable_rewards = true`, the block is permanently marked as processed with no rewards distributed, and no subsequent call can recover rewards for that block. This is the direct analog of the external report's pattern: two related behavioral parameters (`disable_rewards` and the `last_reward_block` state update) are not cross-validated, allowing the reward-safety mechanism to be silently bypassed.

---

### Finding Description

`update_rewards` is part of `IStakingRewardsManager` and is gated only by `general_prerequisites()`, which checks that the contract is not paused and the caller is not the zero address — no role check exists. [1](#0-0) 

Inside the function, `last_reward_block` is written to the current block number **unconditionally**, before the `disable_rewards` branch: [2](#0-1) 

The guard at the top of the function enforces that only one call per block can succeed: [3](#0-2) 

Because `last_reward_block` is already committed when `disable_rewards = true` causes an early return, the slot for that block is consumed with zero rewards distributed. Any legitimate call for the same block will revert with `REWARDS_ALREADY_UPDATED`.

The missing cross-validation is: **if `disable_rewards = true`, `last_reward_block` must not be advanced** (or the function must be restricted to a privileged caller). This is structurally identical to the external report's finding — one parameter (`disable_rewards`, analogous to `LDFType = STATIC`) disables a safety mechanism (reward distribution, analogous to surge fees), while a second behavior (`last_reward_block` advancement, analogous to the shifting distribution) still executes, permanently consuming the processing slot.

---

### Impact Explanation

`last_reward_block` is a **global** state variable shared across all stakers. [4](#0-3) 

A single call with `disable_rewards = true` for any valid staker at block N:
- Advances `last_reward_block` to N.
- Distributes zero rewards to any staker for block N.
- Permanently prevents any other staker from receiving rewards for block N.

An attacker who automates this call every block causes **permanent, total freezing of consensus-era staker yield** — matching the allowed impact: *High: Permanent freezing of unclaimed yield*.

---

### Likelihood Explanation

- `update_rewards` has no role restriction; any EOA can call it.
- The attacker only needs to supply any currently-active staker address (publicly readable from `stakers` vec) and `disable_rewards = true`.
- On Starknet, submitting one transaction per block is trivially automatable and cheap.
- No special knowledge, leaked key, or privileged access is required.

Likelihood: **High**.

---

### Recommendation

Apply one or both of the following fixes:

1. **Move `last_reward_block` write after the `disable_rewards` check**, so a disabled call does not consume the block slot:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
self.last_reward_block.write(current_block_number); // moved here
// ... distribute rewards
```

2. **Add a role check** (e.g., `only_app_governor` or a dedicated `REWARDS_UPDATER` role) so that only the authorized consensus layer can supply `disable_rewards = true`.

---

### Proof of Concept

1. Attacker identifies any valid, active staker address `S` (readable from the public `stakers` storage vector).
2. At block `N`, attacker calls `update_rewards(S, disable_rewards: true)`.
3. `last_reward_block` is written to `N` (line 1485).
4. Function returns early at line 1487 — zero rewards distributed.
5. Any legitimate call to `update_rewards` for block `N` reverts with `REWARDS_ALREADY_UPDATED` (line 1455–1458).
6. Attacker repeats every block → all stakers receive zero consensus rewards indefinitely. [5](#0-4)

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
