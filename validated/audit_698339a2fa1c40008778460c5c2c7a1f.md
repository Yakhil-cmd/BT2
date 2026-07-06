Looking at the external report's vulnerability class — **attacker-controlled input used in a critical accounting calculation** — I need to find an analog in the Starknet Staking codebase where user-supplied data bypasses or corrupts a reward/stake accounting path.

Let me trace the `update_rewards` function and its `disable_rewards` parameter carefully. [1](#0-0) [2](#0-1) 

The global `last_reward_block` is written **before** the `disable_rewards` branch is evaluated, and the function is `#[abi(embed_v0)]` with no access control beyond "not paused / not zero address".

---

### Title
Attacker-Controlled `disable_rewards` Parameter Permanently Freezes Consensus Rewards via Global `last_reward_block` Slot Consumption — (File: `src/staking/staking.cairo`)

---

### Summary

`update_rewards` is a public external function that accepts a caller-controlled `disable_rewards: bool`. It unconditionally writes the current block number to the global `last_reward_block` storage slot **before** checking `disable_rewards`. Any unprivileged actor can call this every block with `disable_rewards: true`, consuming each block's reward slot without distributing rewards, permanently freezing all consensus-phase unclaimed yield.

---

### Finding Description

`update_rewards` in `StakingRewardsManagerImpl` is gated only by `general_prerequisites()` (unpaused + non-zero caller):

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only: unpaused + non-zero caller
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    // ← last_reward_block written HERE, before disable_rewards check
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← exits with no rewards distributed
    }
    ...
}
``` [3](#0-2) 

`last_reward_block` is a **single global** storage variable:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [4](#0-3) 

In V3 consensus rewards, the design is that exactly **one** call to `update_rewards` per block distributes the full block rewards to one staker (the staker's own balance + pool balance sums to the full block reward):

```cairo
let (strk_block_rewards, btc_block_rewards) = self
    .calculate_block_rewards(:reward_supplier_dispatcher, :curr_epoch);
self._update_rewards(
    ...
    strk_total_rewards: strk_block_rewards,
    strk_total_stake: staker_total_strk_balance,   // staker's own total, not network total
    ...
);
``` [5](#0-4) 

Because `last_reward_block` is global and written before the `disable_rewards` branch, a single call with `disable_rewards: true` consumes the entire block's reward slot. No other staker can call `update_rewards` in that block — they receive `REWARDS_ALREADY_UPDATED`.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker calling `update_rewards(any_valid_staker, disable_rewards: true)` every block prevents every staker and every delegation pool from ever accumulating consensus rewards. The full block reward for each block is silently discarded. Since the reward supplier has already accounted for these rewards (via `update_current_epoch_block_rewards`), the funds remain locked in the reward supplier with no path to distribution.

---

### Likelihood Explanation

**High.** The function is fully public with no role check. The only requirements are:
- Contract is not paused
- Caller is a non-zero address
- A valid (active, non-zero-balance) staker address is provided (trivially satisfied by reading any existing staker from the `stakers` vector, which is public via `get_stakers`)

The cost is one transaction per block (gas only). No stake, no privileged key, no special role is required.

---

### Recommendation

1. **Move `last_reward_block.write` to after the `disable_rewards` check**, so a no-op call does not consume the block slot.
2. **Restrict `disable_rewards: true` to a privileged role** (e.g., security agent or governance), or remove the parameter from the public ABI entirely.
3. Consider making `last_reward_block` per-staker rather than global, so one staker's call cannot block all others.

---

### Proof of Concept

```
Block N:
  Attacker calls: staking.update_rewards(staker=<any_valid_staker>, disable_rewards=true)
  → last_reward_block = N
  → returns early, zero rewards distributed

  Legitimate staker calls: staking.update_rewards(staker=<their_address>, disable_rewards=false)
  → assert!(N > N) fails → REWARDS_ALREADY_UPDATED panic

Block N+1:
  Attacker repeats → last_reward_block = N+1
  ...

Result: All consensus block rewards are permanently frozen.
        No staker or pool ever receives consensus-phase yield.
```

The root cause is directly analogous to the `ValidateVoteExtensions` bug: just as `totalVP` was computed from attacker-injected `extCommit.Votes` rather than the authoritative validator set, here the reward-slot accounting (`last_reward_block`) is consumed by an attacker-controlled call with `disable_rewards: true` rather than by a legitimate reward distribution — causing the "total rewards distributed" to be zero instead of the correct block reward amount.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1448-1508)
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
    }
```
