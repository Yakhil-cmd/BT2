### Title
Missing Caller Authorization on `update_rewards` Allows Any Address to Block Reward Distribution - (`File: src/staking/staking.cairo`)

### Summary
The `update_rewards` function in the staking contract is specified to be callable only by the Starknet sequencer, but the implementation contains no caller check. Any unprivileged address can call it with `disable_rewards: true` every block, permanently preventing reward distribution to all stakers.

### Finding Description
The spec for `update_rewards` explicitly states:

> **access control**: Only starkware sequencer.

However, the implementation in `src/staking/staking.cairo` at `StakingRewardsManagerImpl::update_rewards` (lines 1449–1507) performs no caller validation whatsoever. There is no `assert_caller_is_sequencer`, no role check, and a grep across the entire `src/` tree for any sequencer-related guard (`sequencer`, `ONLY_SEQUENCER`, `assert_caller_is_sequencer`, `get_sequencer_address`) returns zero matches.

The function writes a single global `last_reward_block` storage slot to the current block number (line 1485), and the only guard against re-entry is:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

Because `last_reward_block` is a single global value (not per-staker), one call per block by any address is sufficient to consume the slot and prevent the sequencer from distributing rewards in that block.

### Impact Explanation
An attacker calls `update_rewards(any_valid_staker_address, disable_rewards: true)` in every block. Each call:
1. Passes all precondition checks (contract unpaused, staker exists and active, block number advances).
2. Writes `last_reward_block = current_block_number` (line 1485).
3. Returns early because `disable_rewards == true` (line 1487), distributing nothing.

The sequencer's legitimate call in the same block then reverts with `REWARDS_ALREADY_UPDATED`. As long as the attacker front-runs the sequencer each block, **no consensus rewards are ever distributed to any staker or delegator**. This constitutes permanent freezing of unclaimed yield for the entire protocol.

**Impact: High** — Permanent freezing of unclaimed yield / unclaimed royalties.

### Likelihood Explanation
- The entry point is fully public; no stake, role, or special state is required.
- The attacker only needs to submit one transaction per block on Starknet (low fee cost).
- The attack is trivially automatable with a simple bot.
- There is no on-chain mechanism to stop it without a governance pause or contract upgrade.

### Recommendation
Add a sequencer-only guard at the top of `update_rewards`. On Starknet, the sequencer address is available via `starknet::get_execution_info().caller_address` when called as the first transaction in a block, or the protocol should store a trusted sequencer address and assert:

```cairo
fn update_rewards(...) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    // ... rest of function
}
```

Alternatively, restrict the interface so only a whitelisted address (set at initialization) may call this function, mirroring the pattern already used for `update_rewards_from_attestation_contract` which correctly asserts `self.assert_caller_is_attestation_contract()`.

### Proof of Concept

1. Deploy the staking system and advance to consensus rewards epoch.
2. Stake as a legitimate staker.
3. As an unprivileged attacker address, call:
   ```
   IStakingRewardsManagerDispatcher { contract_address: staking_contract }
       .update_rewards(staker_address: any_active_staker, disable_rewards: true);
   ```
4. Observe: `last_reward_block` is now set to the current block. The sequencer's call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeat step 3 in every subsequent block.
6. Observe: `staker_info.unclaimed_rewards_own` never increases; no rewards are ever distributed.

**Root cause**: `src/staking/staking.cairo`, lines 1449–1507 — `StakingRewardsManagerImpl::update_rewards` — no caller authorization check despite the spec mandating "Only starkware sequencer." [1](#0-0) [2](#0-1) [3](#0-2)

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
