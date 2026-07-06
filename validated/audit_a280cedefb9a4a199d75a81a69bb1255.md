### Title
Unprivileged Caller Can Grief All Consensus Block Rewards by Consuming `last_reward_block` Slot — (`File: src/staking/staking.cairo`)

---

### Summary

`update_rewards` in `staking.cairo` has no access-control guard beyond "caller is not zero". Any unprivileged address can call it with `disable_rewards: true`, which writes the current block number to the global `last_reward_block` storage slot **before** the early-return that skips reward distribution. Because the function enforces a strict "one call per block" invariant, the legitimate sequencer call in the same block is permanently rejected with `REWARDS_ALREADY_UPDATED`, and no staker receives consensus block rewards for that block.

---

### Finding Description

`IStakingRewardsManager::update_rewards` is documented in the spec as callable only by the Starkware sequencer:

> **access control**: Only starkware sequencer.

However, the implementation enforces no such restriction. The only gate is `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [1](#0-0) 

Inside `update_rewards`, the global `last_reward_block` is written **unconditionally** — before the `disable_rewards` branch that skips actual reward computation:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [2](#0-1) 

The guard that prevents a second call in the same block is:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [3](#0-2) 

Because `last_reward_block` is a **single global slot** (not per-staker), one successful call in a block locks out every other call for that block, regardless of which staker is targeted.

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` in every block:
1. Satisfies all checks (unpaused, non-zero caller, block > last_reward_block, staker active with non-zero balance).
2. Writes `last_reward_block = current_block`.
3. Returns early — zero rewards distributed.
4. The sequencer's legitimate call in the same block fails with `REWARDS_ALREADY_UPDATED`.

The attacker needs no privileged role, no tokens, and no approval. They only need to know any valid active staker address (publicly readable from `stakers` vector or events). [4](#0-3) 

---

### Impact Explanation

All consensus block rewards (`strk_block_rewards`, `btc_block_rewards`) are permanently withheld from every staker and every delegation pool for as long as the attacker sustains the attack. `unclaimed_rewards_own` is never incremented; pool contracts never receive their share. This constitutes **permanent freezing of unclaimed yield** (High) or at minimum **temporary freezing** (High) while the attack is active. [5](#0-4) 

---

### Likelihood Explanation

- The entry point is fully public — no role, no token balance, no approval required.
- The attacker only needs one cheap transaction per block.
- On Starknet, transaction fees are low, making sustained griefing economically viable.
- Any active staker address is discoverable on-chain from the `stakers` vector. [6](#0-5) 

---

### Recommendation

Add an access-control check at the top of `update_rewards` that restricts callers to the designated sequencer role (or a dedicated `REWARDS_MANAGER` role), consistent with the spec's stated intent:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.roles.only_sequencer(); // enforce spec access control
    ...
}
```

Alternatively, move the `last_reward_block.write(current_block_number)` to **after** the `disable_rewards` guard so that a no-op call does not consume the block's reward slot. [7](#0-6) 

---

### Proof of Concept

```
// Attacker script — run once per block
// Precondition: `active_staker` is any staker with non-zero balance at current epoch

loop {
    wait_for_new_block();
    staking_rewards_manager.update_rewards(
        staker_address: active_staker,
        disable_rewards: true   // skips reward distribution but still writes last_reward_block
    );
    // Sequencer's legitimate update_rewards call in this block now reverts with REWARDS_ALREADY_UPDATED
    // No staker or pool receives block rewards for this block
}
```

The attacker pays only gas per block. All stakers' `unclaimed_rewards_own` and all pool `cumulative_rewards_trace` entries remain frozen for the duration of the attack. [4](#0-3) [1](#0-0)

### Citations

**File:** src/staking/staking.cairo (L168-170)
```text
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
        /// Map token address to its decimals.
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
