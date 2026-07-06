### Title
Unrestricted `disable_rewards` Parameter in `update_rewards` Allows Any Caller to Permanently Deny Consensus Rewards to All Stakers - (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract accepts a caller-controlled `disable_rewards: bool` parameter with no access control. Any unprivileged address can call `update_rewards(any_valid_staker, disable_rewards: true)` once per block. Because `last_reward_block` is written to storage **before** the early-return guard, the block's reward slot is permanently consumed without distributing any rewards. An attacker who does this every block denies all stakers their consensus-era yield indefinitely.

---

### Finding Description

`update_rewards` is part of the public `IStakingRewardsManager` interface. Its only gate is `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero — no check that the caller is the staker, the operational address, or any privileged role.

```cairo
// src/staking/staking.cairo  ~line 1449
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only: unpaused + caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    // Update last block rewards.
    self.last_reward_block.write(current_block_number);   // ← slot consumed HERE

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← rewards skipped
    }
    ...
```

`last_reward_block` is a **single global value** shared across all stakers. Once it is written to the current block number, no further call to `update_rewards` can succeed for that block (the `REWARDS_ALREADY_UPDATED` assertion fires). The attacker only needs to supply any currently-active staker address with non-zero balance to pass the validity checks.

The attack path:

1. Attacker calls `update_rewards(any_active_staker, disable_rewards: true)` in block N.
2. `last_reward_block` is set to N; the function returns early — zero rewards distributed.
3. Any legitimate call to `update_rewards` in block N now reverts with `REWARDS_ALREADY_UPDATED`.
4. Repeat every block → all stakers accumulate zero consensus rewards indefinitely.

---

### Impact Explanation

Consensus rewards (V3 mode) are distributed exactly once per block via `update_rewards`. By consuming the per-block slot with `disable_rewards: true`, the attacker causes every staker's `unclaimed_rewards_own` to remain at zero. Sustained over time this constitutes **permanent freezing of unclaimed yield** for the entire protocol — matching the High impact tier.

---

### Likelihood Explanation

- The function is publicly callable with no role restriction.
- The attacker needs only a valid, active staker address (publicly readable from events or `get_stakers`).
- The cost is one transaction per block (gas only); no capital is required.
- The attack is trivially automatable with a simple keeper bot.

---

### Recommendation

Remove the `disable_rewards` parameter from the public interface entirely, or restrict who may pass `true` to a privileged role (e.g., `only_security_agent`). If the parameter is needed for migration purposes, gate it behind an access-control check:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    if disable_rewards {
        self.roles.only_security_agent();   // or equivalent privileged check
    }
    ...
```

Additionally, consider moving the `last_reward_block.write(current_block_number)` to **after** the `disable_rewards` guard so that a privileged skip does not permanently consume the block's reward slot for all other stakers.

---

### Proof of Concept

```
// Attacker script (pseudocode, one call per block)
loop {
    staking_contract.update_rewards(
        staker_address = any_active_staker,   // e.g. read from NewStaker events
        disable_rewards = true
    );
    wait_for_next_block();
}
```

After this loop runs for an epoch, every staker's `unclaimed_rewards_own` remains zero. The `last_reward_block` storage slot is updated each block, so no legitimate `update_rewards(staker, false)` call can succeed in the same block.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/staking/staking.cairo (L1449-1508)
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
