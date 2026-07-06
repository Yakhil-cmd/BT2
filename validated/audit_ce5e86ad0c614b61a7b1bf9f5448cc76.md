### Title
Unrestricted `update_rewards` with `disable_rewards: true` Allows Any Caller to Permanently Grief Block Reward Distribution - (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract has no access control and exposes a `disable_rewards` boolean parameter to any caller. An unprivileged attacker can call `update_rewards(any_active_staker, disable_rewards: true)` every block to consume the global per-block reward slot (`last_reward_block`) without distributing any rewards. All subsequent legitimate calls in the same block revert with `REWARDS_ALREADY_UPDATED`, permanently preventing block reward distribution for every block the attacker targets.

---

### Finding Description

`update_rewards` is gated only by `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero — no role or identity check. [1](#0-0) 

The function's execution path is:

1. Assert `current_block_number > last_reward_block` (global storage).
2. Validate the supplied `staker_address` is active with non-zero balance.
3. **Write `last_reward_block = current_block_number`** — this happens unconditionally before the `disable_rewards` branch.
4. If `disable_rewards || is_pre_consensus()` → return early, distributing nothing. [2](#0-1) 

`last_reward_block` is a **single global variable** shared across all stakers: [3](#0-2) 

Because the write to `last_reward_block` occurs before the `disable_rewards` guard, any caller who invokes `update_rewards(valid_staker, disable_rewards: true)` in block N:

- Advances `last_reward_block` to N.
- Distributes zero rewards.
- Causes every subsequent `update_rewards` call in block N to revert with `REWARDS_ALREADY_UPDATED` (the `current_block_number > last_reward_block` assertion fails).

---

### Impact Explanation

Block rewards are calculated and distributed inside `_update_rewards`, which is only reached when `disable_rewards` is false and the contract is in the consensus-rewards phase. [4](#0-3) 

When the attacker front-runs every block with `disable_rewards: true`, `_update_rewards` is never reached. Staker `unclaimed_rewards_own` is never incremented, and pool reward traces are never updated. Stakers and delegators accumulate zero yield. Because the attack can be repeated indefinitely at the cost of one transaction per block, this constitutes **permanent freezing of unclaimed yield** for all protocol participants — matching the High impact tier.

---

### Likelihood Explanation

- No privileged role is required; any non-zero address suffices.
- The attacker only needs to know one active staker address, which is fully public on-chain (emitted in `NewStaker` events and readable via `get_stakers`).
- The cost is one cheap transaction per block. On Starknet, block times are short (~3 s), making sustained griefing economically feasible for a motivated attacker.
- There is no slashing or penalty mechanism that deters the attacker.

---

### Recommendation

Restrict `update_rewards` to a trusted caller (e.g., the consensus layer address, or a dedicated `REWARDS_MANAGER` role). The `disable_rewards` flag, if needed at all, should be callable only by a privileged role. A minimal fix:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.roles.only_rewards_manager(); // add role check
    ...
}
```

Alternatively, remove the `disable_rewards` parameter from the public interface entirely and handle the pre-consensus early-return internally.

---

### Proof of Concept

```
Block N:
  Attacker tx:  update_rewards(active_staker_A, disable_rewards=true)
    → last_reward_block := N
    → returns early, no rewards distributed

  Legitimate tx: update_rewards(active_staker_A, disable_rewards=false)
    → assert(N > N) FAILS → REWARDS_ALREADY_UPDATED revert

Block N+1:
  Attacker repeats → last_reward_block := N+1 → no rewards
  ...
```

The attacker repeats this every block. `unclaimed_rewards_own` for every staker remains at its initial value; pool `cumulative_rewards_trace` is never updated; delegators earn nothing. The protocol's entire consensus-phase reward mechanism is silently neutralised. [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

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
