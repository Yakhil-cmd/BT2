### Title
Unprivileged `update_rewards(disable_rewards: true)` Permanently Blocks All Consensus Rewards — (`File: src/staking/staking.cairo`)

---

### Summary

`update_rewards` is a publicly callable function with no privileged-role guard. When called with `disable_rewards: true`, it writes the current block number to `last_reward_block` **before** checking the flag, then returns early without distributing any rewards. Because the contract enforces a one-call-per-block invariant via `last_reward_block`, an unprivileged attacker who calls this function every block permanently prevents every staker from receiving consensus rewards.

---

### Finding Description

`update_rewards` is exposed as `#[abi(embed_v0)]` under `StakingRewardsManagerImpl`. Its only gate is `general_prerequisites`, which checks that the contract is not paused and the caller is non-zero — no role check exists. [1](#0-0) 

Inside the function, `last_reward_block` is written unconditionally before the `disable_rewards` branch: [2](#0-1) [3](#0-2) 

The sequence is:
1. Assert `current_block > last_reward_block` (one-call-per-block gate).
2. **Write** `last_reward_block = current_block`.
3. If `disable_rewards` → **return early** with no rewards distributed.

Because step 2 happens before step 3, a call with `disable_rewards: true` marks the block as "processed" while leaving every staker's `unclaimed_rewards_own` unchanged. Any legitimate `update_rewards` call in the same block then fails at step 1 with `REWARDS_ALREADY_UPDATED`.

This is the direct analog to the original report: an unprivileged operation (`ExtendProgramData` / `update_rewards`) modifies one piece of state (account data length / `last_reward_block`) without updating the dependent state (cached ELF / staker rewards), creating a persistent inconsistency that blocks correct operation.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` in every block indefinitely denies all stakers their consensus-phase block rewards. The `last_reward_block` is a single global slot; consuming it with a no-op call starves the entire protocol of reward distribution. Stakers' `unclaimed_rewards_own` balances never grow, constituting a permanent freeze of unclaimed yield. [4](#0-3) 

---

### Likelihood Explanation

**High.** The function is permissionless — any EOA or contract can call it. The only cost is gas per block. On Starknet, transaction fees are low, making sustained block-by-block griefing economically viable. No leaked key, privileged role, or external dependency is required.

---

### Recommendation

Add an access-control check so that only the designated consensus contract (or a privileged role) may call `update_rewards`. For example:

```cairo
fn update_rewards(ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool) {
    self.general_prerequisites();
    self.assert_caller_is_consensus_contract(); // <-- add this
    ...
}
```

Alternatively, move the `last_reward_block.write` to **after** the `disable_rewards` guard so that a no-op call does not consume the block's reward slot.

---

### Proof of Concept

```
// Attacker script (pseudocode, runs every block)
loop {
    staking_contract.update_rewards(
        staker_address = any_valid_staker,
        disable_rewards = true
    );
    // last_reward_block = current_block
    // No rewards distributed
    // All other update_rewards calls in this block revert with REWARDS_ALREADY_UPDATED
    wait_for_next_block();
}
```

1. Attacker picks any active staker address (readable from the public `stakers` vector).
2. Calls `update_rewards(staker, true)` in block N → `last_reward_block` = N, no rewards sent.
3. Any honest call to `update_rewards` in block N reverts.
4. Repeat each block. All stakers are permanently denied consensus rewards at the cost of gas only. [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L1448-1507)
```text
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
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
