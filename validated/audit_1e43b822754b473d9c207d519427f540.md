### Title
Any Caller Can Permanently Freeze Consensus Rewards by Calling `update_rewards` with `disable_rewards: true` — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in `IStakingRewardsManager` has no access control and accepts a user-supplied `disable_rewards` boolean. Any unprivileged caller can invoke it with `disable_rewards: true` every block, consuming the global per-block reward slot (`last_reward_block`) without distributing any rewards. This permanently prevents all stakers from accruing consensus-era yield.

---

### Finding Description

`update_rewards` is a public function callable by any non-zero address:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();   // only checks: not paused, caller != zero
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    self.last_reward_block.write(current_block_number);   // ← global slot consumed

    if disable_rewards || self.is_pre_consensus() {
        return;   // ← exits without distributing any rewards
    }
    ...
``` [1](#0-0) 

`last_reward_block` is a **single global variable** shared across all stakers. Once it is written to the current block number, no other call to `update_rewards` can succeed in the same block (the `REWARDS_ALREADY_UPDATED` assertion fires). [2](#0-1) 

`general_prerequisites` enforces only two conditions — contract not paused and caller not zero — with no role or identity check: [3](#0-2) 

The `disable_rewards` parameter is therefore entirely attacker-controlled and is never validated against any stored state or caller identity.

**Attack path:**

1. Attacker (any non-zero address) calls `update_rewards(any_valid_staker_address, disable_rewards: true)` once per block.
2. `last_reward_block` is set to the current block number.
3. The function returns early — no rewards are distributed to any staker or pool.
4. Any legitimate consensus-layer call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeating this every block (trivially automatable on Starknet) permanently prevents all stakers from receiving consensus rewards.

---

### Impact Explanation

All stakers are permanently denied consensus-era yield. The `unclaimed_rewards_own` field of every staker remains at zero indefinitely. Pool members also receive no rewards because pool reward forwarding (`_update_rewards` → `send_rewards_to_delegation_pool`) is never reached. [4](#0-3) 

This matches the allowed impact: **High — Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

- No special privilege is required; any externally-owned account suffices.
- The only cost is gas per block, which is negligible on Starknet L2.
- The attack is fully automatable with a simple script.
- There is no on-chain mechanism to evict the attacker or reset `last_reward_block` independently of a legitimate `update_rewards` call.

---

### Recommendation

Add an access-control check so that only the designated consensus/sequencer address (or a whitelisted set of callers) may supply `disable_rewards: true`. One approach:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
+   if disable_rewards {
+       self.roles.only_rewards_manager();  // or equivalent privileged role
+   }
    ...
```

Alternatively, derive `disable_rewards` from on-chain state (e.g., whether the staker submitted a valid attestation/block proposal) rather than accepting it as a caller-supplied parameter.

---

### Proof of Concept

```cairo
// Any address can call this every block to freeze all consensus rewards.
fn attack(staking_contract: ContractAddress, any_valid_staker: ContractAddress) {
    let rewards_dispatcher = IStakingRewardsManagerDispatcher {
        contract_address: staking_contract,
    };
    // Called once per block — consumes last_reward_block, distributes nothing.
    rewards_dispatcher.update_rewards(
        staker_address: any_valid_staker,
        disable_rewards: true,
    );
    // After this call, every other update_rewards call in this block reverts
    // with REWARDS_ALREADY_UPDATED.
}
```

The existing test suite confirms the mechanics: [5](#0-4) 

`last_reward_block` is written unconditionally before the `disable_rewards` branch, so the slot is consumed regardless of whether rewards are actually distributed.

### Citations

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
