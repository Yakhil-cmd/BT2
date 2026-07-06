### Title
`last_reward_block` Updated Before Early Return in `update_rewards` Allows Permanent Freezing of Block Rewards — (File: `src/staking/staking.cairo`)

---

### Summary

`update_rewards` in `Staking` writes `last_reward_block` to storage **before** a conditional early return. An unprivileged caller can invoke `update_rewards(valid_staker, disable_rewards: true)`, consuming the block's reward slot without distributing any rewards. Because `last_reward_block` is now set to the current block, every subsequent call for that block reverts with `REWARDS_ALREADY_UPDATED`, permanently destroying that block's rewards for all stakers.

---

### Finding Description

In `StakingRewardsManagerImpl::update_rewards`, the global `last_reward_block` is written **before** the conditional early-return guard: [1](#0-0) 

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // ← state committed

if disable_rewards || self.is_pre_consensus() {
    return;                                            // ← early exit, no rewards distributed
}
```

The function's only access control is `general_prerequisites()`, which checks only the pause flag and a non-zero caller: [2](#0-1) 

There is no role check. Any address can call `update_rewards` with an arbitrary `disable_rewards: bool` parameter.

The guard at the top of the function enforces that `update_rewards` can be called **at most once per block**: [3](#0-2) 

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

Because `last_reward_block` is written before the early return, a call with `disable_rewards: true` permanently marks the block as processed while skipping the actual reward distribution path: [4](#0-3) 

The rewards that would have been distributed via `_update_rewards` → `calculate_block_rewards` → `update_pool_rewards` are simply never computed or sent. There is no recovery path.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

`last_reward_block` is a **global** slot: once consumed for a given block number, no staker can receive block rewards for that block. The rewards are not deferred; they are permanently lost. An attacker who calls `update_rewards(any_active_staker, true)` once per block eliminates all consensus-phase block rewards for every staker and every delegation pool indefinitely.

---

### Likelihood Explanation

**High.** The function is publicly callable with no role restriction. The only prerequisite is supplying a valid, active staker address, which is trivially obtained from on-chain events (`NewStaker`). The attacker spends only gas and gains nothing, making this a pure griefing vector, but the barrier to execution is minimal.

---

### Recommendation

Move `self.last_reward_block.write(current_block_number)` to **after** the early-return guard, so the block slot is only consumed when rewards are actually distributed:

```cairo
// ❌ Current (vulnerable)
self.last_reward_block.write(current_block_number);
if disable_rewards || self.is_pre_consensus() {
    return;
}

// ✅ Fixed
if disable_rewards || self.is_pre_consensus() {
    return;
}
self.last_reward_block.write(current_block_number);
```

This mirrors the fix described in the reference report: move the state-mutating operation to after the conditional that may cause an early exit, so the state is only committed when the full execution path completes.

---

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. A new block `N` is produced. `last_reward_block < N`.
3. Attacker calls `Staking::update_rewards(active_staker_address, disable_rewards: true)`.
4. `general_prerequisites()` passes (contract not paused, caller non-zero).
5. `current_block_number (N) > last_reward_block` — assertion passes.
6. Staker validity checks pass (attacker used a real active staker address).
7. `last_reward_block.write(N)` executes — block slot consumed.
8. `disable_rewards == true` → early return. No rewards distributed.
9. Any legitimate call to `update_rewards` for block `N` now reverts with `REWARDS_ALREADY_UPDATED`.
10. Block `N`'s rewards are permanently lost for all stakers and pools. [5](#0-4)

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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
