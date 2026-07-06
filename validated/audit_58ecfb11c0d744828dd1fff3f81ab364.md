### Title
Missing Access Control on `update_rewards()` Allows Any Caller to Block Reward Distribution - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in `StakingRewardsManagerImpl` is callable by any address despite the specification explicitly requiring "Only starkware sequencer." An unprivileged caller can invoke it with `disable_rewards: true` to consume the per-block update slot without distributing any rewards, permanently blocking the sequencer's legitimate call for that block.

### Finding Description

The specification at `docs/spec.md` line 1645 states:

> **access control**: Only starkware sequencer.

However, the implementation at `src/staking/staking.cairo` lines 1447–1507 contains no caller check whatsoever:

```cairo
#[abi(embed_v0)]
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
        // ... no assert_caller_is_sequencer or equivalent ...
        self.last_reward_block.write(current_block_number);   // ← global slot consumed
        if disable_rewards || self.is_pre_consensus() {
            return;   // ← exits without distributing anything
        }
        // reward distribution follows only if we reach here
    }
}
```

`last_reward_block` is a **global** (non-per-staker) storage variable. [1](#0-0) 

The guard at line 1454–1458 enforces that only one call per block is accepted. [2](#0-1) 

Once `last_reward_block` is written to the current block number (line 1485), every subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`. [3](#0-2) 

The spec's access-control requirement is documented but never enforced in code. [4](#0-3) 

### Impact Explanation

**Permanent freezing of unclaimed yield (High) / Griefing (Medium)**

An attacker calls `update_rewards(any_active_staker, disable_rewards: true)` before the sequencer in a given block. This:

1. Writes `last_reward_block = current_block` with zero rewards distributed.
2. Causes the sequencer's legitimate call for **any** staker in the same block to revert with `REWARDS_ALREADY_UPDATED`.
3. Because `last_reward_block` is global, a single attacker transaction blocks reward distribution for **all** stakers in that block.

If repeated across consecutive blocks, stakers accumulate zero `unclaimed_rewards_own` indefinitely — a permanent freeze of unclaimed yield. The attacker spends only gas; no profit is required.

### Likelihood Explanation

- The function is part of the public ABI (`IStakingRewardsManager`) with no modifier or caller assertion.
- Tests confirm any address can call it without impersonating the sequencer (e.g., `test_update_rewards_only_staker` at line 3488 calls it with no `cheat_caller_address`). [5](#0-4) 
- The attacker only needs to submit a cheap transaction per block; the cost is minimal gas.
- On Starknet, user transactions and sequencer transactions share the same mempool ordering; if the sequencer's reward call is not a privileged system call, it can be front-run.

### Recommendation

Add a sequencer-only guard. On Starknet the sequencer address is available via `starknet::get_execution_info().caller_address` when called as a system call, or store a configurable `sequencer_address` and assert:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    // ... rest of logic
}
```

Alternatively, expose a role (e.g., `REWARDS_MANAGER`) granted only to the sequencer address, consistent with the existing `RolesComponent` pattern already used in the contract. [6](#0-5) 

### Proof of Concept

1. Staker stakes and K epochs pass so `staker_total_strk_balance > 0`.
2. Consensus rewards are active (`!is_pre_consensus()`).
3. Attacker (any EOA) calls:
   ```
   IStakingRewardsManager(staking_contract).update_rewards(staker_address, disable_rewards: true)
   ```
4. `last_reward_block` is set to the current block; no rewards are distributed.
5. Sequencer's call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
6. Staker's `unclaimed_rewards_own` remains zero for that block.
7. Repeat step 3 every block → staker never accumulates rewards. [7](#0-6) [8](#0-7)

### Citations

**File:** src/staking/staking.cairo (L1447-1508)
```text
    #[abi(embed_v0)]
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
