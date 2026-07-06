### Title
Unrestricted `update_rewards` Allows Any Staker to Monopolize All Block Rewards - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the staking contract is specified as "Only starkware sequencer" in the protocol spec, but the implementation enforces no such caller restriction. Any address can call it. Because the guard `last_reward_block` is a **global** (not per-staker) variable, a staker who calls `update_rewards` for themselves every block will set `last_reward_block` to the current block, causing every subsequent sequencer call for any other staker in that same block to revert with `REWARDS_ALREADY_UPDATED`. By front-running the sequencer every block, the attacker monopolizes all block rewards and permanently freezes other stakers' unclaimed yield.

---

### Finding Description

The `IStakingRewardsManager.update_rewards` function is the V3 (consensus-phase) reward distribution entry point:

```cairo
// src/staking/staking.cairo ~L1449
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks pause
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    self.last_reward_block.write(current_block_number);   // GLOBAL write
    ...
    self._update_rewards(...);   // increases staker_info.unclaimed_rewards_own
}
```

The spec at `docs/spec.md` line 1645 states:

> **access control**: Only starkware sequencer.

But the implementation contains **no caller check** — `general_prerequisites()` is also called by `claim_rewards` and `unstake_intent` (functions callable by ordinary users), so it cannot contain a sequencer guard. The only protection is the global `last_reward_block` guard, which prevents two calls in the same block but does not restrict *who* may call.

The analog to the FLUX `poke` vulnerability is exact:

| FLUX (Alchemix) | Starknet Staking |
|---|---|
| `poke()` is public | `update_rewards()` has no caller check |
| `accrueFlux()` increases balance each call | `_update_rewards()` increases `unclaimed_rewards_own` each call |
| No per-epoch guard on `accrueFlux` | No per-block guard *per staker*; guard is global |
| Attacker calls `poke` N times → N × claimableFlux | Attacker calls every block → gets rewards every block, others get zero |

---

### Impact Explanation

`last_reward_block` is a single global storage slot. When the attacker calls `update_rewards(staker_address=attacker, disable_rewards=false)` in block N:

1. `last_reward_block` is set to N.
2. The attacker's `unclaimed_rewards_own` is increased by one block's worth of rewards.
3. Any subsequent call in block N (including the sequencer's call for another staker) reverts with `REWARDS_ALREADY_UPDATED`.

By repeating this every block, the attacker:
- Receives rewards in **every** block instead of their proportional share.
- Causes every other staker to receive **zero** rewards indefinitely.

This constitutes both **theft of unclaimed yield** (attacker receives yield belonging to other stakers) and **permanent freezing of unclaimed yield** for all other stakers — both High-severity impacts in the allowed scope.

---

### Likelihood Explanation

- The attacker only needs to be a registered staker (permissionless entry via `stake()`).
- The attack requires submitting one transaction per block — straightforward on Starknet.
- No privileged access, no leaked keys, no external dependencies.
- The attack is profitable: the attacker receives all block rewards instead of their proportional share.

---

### Recommendation

Add an explicit sequencer-address check to `update_rewards`, consistent with the spec. Store the authorized sequencer address in contract storage and assert it at the top of the function:

```cairo
fn update_rewards(...) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    ...
}
```

Alternatively, if the sequencer address is not known at deploy time, use a role-based check (e.g., a `REWARDS_MANAGER` role) consistent with the existing `RolesComponent` pattern already used throughout the contract.

---

### Proof of Concept

```
// Attacker is a registered staker with any non-zero stake.
// Runs once per block (e.g., via a keeper bot or direct submission):

loop {
    staking.update_rewards(
        staker_address: attacker_address,
        disable_rewards: false,
    );
    // last_reward_block = current_block
    // attacker.unclaimed_rewards_own += block_rewards
    // sequencer's call for any other staker in this block → REWARDS_ALREADY_UPDATED
    advance_to_next_block();
}

// After N blocks:
// attacker.unclaimed_rewards_own = N * block_rewards  (should be ~attacker_share * N * block_rewards)
// all other stakers: unclaimed_rewards_own unchanged (frozen)
staking.claim_rewards(staker_address: attacker_address);
// attacker receives all N blocks of rewards
```

**Key references:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** docs/spec.md (L1626-1652)
```markdown
### update_rewards
```rust
fn update_rewards(ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool);
```
#### description <!-- omit from toc -->
Calculate and update the current block rewards for the for the given `staker_address`.
Send pool rewards to the pools.
Distribute rewards only if `disable_rewards` is False and consensus rewards already started.
#### emits <!-- omit from toc -->
1. [Staker Rewards Updated](#staker-rewards-updated)
2. [Rewards Supplied To Delegation Pool](#rewards-supplied-to-delegation-pool)
#### errors <!-- omit from toc -->
1. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
2. [REWARDS\_ALREADY\_UPDATED](#rewards_already_updated)
3. [STAKER\_NOT\_EXISTS](#staker_not_exists)
4. [INVALID\_STAKER](#invalid_staker)
#### pre-condition <!-- omit from toc -->
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
1. Calculate total block rewards.
2. Calculate staker rewards (include commission) and pool rewards.
3. Update `unclaimed_rewards_own` of the staker.
4. Update and transfer rewards to the pools, if exist.
5. Update Reward Supplier's `unclaimed_rewards`.
6. Update `last_reward_block` to the current block.
```

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
