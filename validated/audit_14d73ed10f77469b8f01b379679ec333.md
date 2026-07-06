The key facts from the code:

1. **Spec says** "Only starkware sequencer" for `update_rewards` access control [1](#0-0) 

2. **Implementation has no such check** — only `general_prerequisites()` (pause check) is called before proceeding: [2](#0-1) 

3. **`last_reward_block` is a global, not per-staker** — one successful call per block for the entire contract: [3](#0-2) 

4. **`disable_rewards: true` writes `last_reward_block` then returns early** with no reward distribution: [4](#0-3) 

---

### Title
Missing Sequencer-Only Access Control on `update_rewards` Allows Any Caller to Permanently Suppress Per-Block Rewards — (File: src/staking/staking.cairo)

### Summary
`IStakingRewardsManager::update_rewards` is callable by any address. The spec mandates "Only starkware sequencer" access, but the implementation enforces no caller check. An unprivileged attacker can call `update_rewards(any_valid_staker, disable_rewards: true)` once per block, consuming the global `last_reward_block` slot and permanently discarding that block's consensus rewards for all stakers.

### Finding Description
`update_rewards` is the sole path for distributing per-block consensus rewards. Its guard is:

```cairo
// src/staking/staking.cairo:1452-1488
self.general_prerequisites();          // only checks pause
assert!(current_block_number > self.last_reward_block.read(), ...REWARDS_ALREADY_UPDATED);
// ...
self.last_reward_block.write(current_block_number);   // global, not per-staker
if disable_rewards || self.is_pre_consensus() {
    return;   // exits with no reward distribution
}
```

`last_reward_block` is a single global value. Once written for block N, every subsequent call in block N reverts with `REWARDS_ALREADY_UPDATED`. Passing `disable_rewards: true` writes the block number and returns immediately — no rewards are credited to any staker or pool. Because the slot is consumed, the legitimate sequencer call that would have distributed rewards can never succeed for that block.

### Impact Explanation
Each block's rewards are permanently lost — they are never minted/credited to `unclaimed_rewards_own` or forwarded to delegation pools. Repeated across many blocks this constitutes permanent freezing of unclaimed yield. Matches **High: Permanent freezing of unclaimed yield**.

### Likelihood Explanation
The call is permissionless, costs only gas, and requires only a valid (active, post-K-epoch) staker address as argument — trivially discoverable on-chain. The attacker needs no stake, no role, and no special knowledge beyond the staker address.

### Recommendation
Add a sequencer-only (or at minimum a whitelisted-caller) check at the top of `update_rewards`, consistent with the spec's stated access control. For example, assert `get_caller_address() == sequencer_address` before any state mutation.

### Proof of Concept
1. Deploy with two active stakers, consensus rewards active.
2. From an arbitrary EOA, call `update_rewards(staker_A, disable_rewards: true)` at block N.
3. Observe `last_reward_block` is now N.
4. Attempt the legitimate sequencer call `update_rewards(staker_A, disable_rewards: false)` — reverts with `REWARDS_ALREADY_UPDATED`.
5. Advance to block N+1; staker_A's `unclaimed_rewards_own` has not increased for block N.
6. Repeat for every block: cumulative rewards remain zero while the model predicts non-zero accrual. [5](#0-4) [6](#0-5)

### Citations

**File:** docs/spec.md (L1626-1653)
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
