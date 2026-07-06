### Title
Unrestricted `update_rewards` with `disable_rewards=true` Allows Any Caller to Permanently Freeze Block Rewards for All Stakers - (File: src/staking/staking.cairo)

---

### Summary

The `IStakingRewardsManager::update_rewards` function in `staking.cairo` is publicly callable by any address and accepts a `disable_rewards: bool` parameter. When called with `disable_rewards=true`, it advances the global `last_reward_block` state variable to the current block without distributing any rewards. Because there is no caller authentication, an attacker can call this function every block with `disable_rewards=true` to permanently prevent all stakers from receiving consensus block rewards.

---

### Finding Description

The vulnerability class from the external report is **authorization bypass**: a function that takes a user-controlled address parameter and performs privileged state changes without verifying that `msg.sender` is the authorized party. The analog here is that `update_rewards` performs a privileged global state mutation (`last_reward_block`) without any caller check, and exposes a `disable_rewards` flag that any caller can set to suppress reward distribution.

`update_rewards` is defined in `IStakingRewardsManager`: [1](#0-0) 

Its implementation in `staking.cairo`: [2](#0-1) 

The critical sequence inside the function is:

1. Assert `current_block_number > self.last_reward_block.read()` — enforces one call per block globally.
2. Validate that `staker_address` is an active staker with non-zero balance.
3. **Write `self.last_reward_block.write(current_block_number)`** — this is the global gate update.
4. If `disable_rewards || self.is_pre_consensus()` → **return early, no rewards distributed**. [3](#0-2) 

`last_reward_block` is a single global storage slot, not per-staker: [4](#0-3) 

There is no `assert_caller_is_*` or role check anywhere in `update_rewards`. The only prerequisite is `general_prerequisites()`, which only checks the pause flag: [5](#0-4) 

An attacker therefore:
1. Identifies any valid active staker address (publicly available from `NewStaker` events).
2. Calls `update_rewards(valid_staker, disable_rewards=true)` in every block.
3. `last_reward_block` is advanced to the current block with no rewards distributed.
4. Any subsequent legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`. [6](#0-5) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield for all stakers.**

`last_reward_block` is a single global variable. One attacker call per block with `disable_rewards=true` is sufficient to suppress block reward distribution for every staker in the protocol for that block. Repeated every block, this permanently freezes all consensus block rewards. The attacker gains nothing financially, but the entire staker population is denied yield indefinitely at the cost of gas per block.

---

### Likelihood Explanation

**High.** The function is part of a public ABI interface (`IStakingRewardsManager`) with no access control. Any EOA or contract can call it. The only input required is a valid active staker address, which is trivially obtained from on-chain `NewStaker` events. The attack requires one transaction per block — feasible and cheap on Starknet.

---

### Recommendation

Restrict `update_rewards` to a trusted caller. Options:

- Add a role check (e.g., `only_app_governor` or a dedicated `REWARDS_MANAGER` role) so only an authorized address can call it.
- If `disable_rewards` is only needed during the pre-consensus transition, remove the parameter entirely and handle the `is_pre_consensus()` branch internally.
- If the function must remain permissionless (e.g., for sequencer-agnostic reward triggering), remove the `disable_rewards` parameter so callers cannot suppress distribution.

---

### Proof of Concept

```
Setup:
  - Alice is a registered active staker (address known from NewStaker event).
  - Consensus rewards are active (is_pre_consensus() == false).

Attack loop (every block N):
  1. Attacker calls: staking.update_rewards(alice_address, disable_rewards=true)
     → last_reward_block is written to N.
     → Early return: no rewards distributed.

  2. Legitimate reward distributor calls: staking.update_rewards(alice_address, disable_rewards=false)
     → Assertion fails: current_block_number (N) > last_reward_block (N) is FALSE.
     → Reverts with REWARDS_ALREADY_UPDATED.

Result: No staker receives block rewards for block N.
Repeat every block → permanent freeze of all consensus block rewards.
```

### Citations

**File:** src/staking/interface.cairo (L303-311)
```text
#[starknet::interface]
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```

**File:** src/staking/staking.cairo (L187-188)
```text
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
