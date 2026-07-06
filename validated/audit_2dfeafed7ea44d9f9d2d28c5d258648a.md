### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Block Reward Distribution - (File: src/staking/staking.cairo)

### Summary
`IStakingRewardsManager::update_rewards` in `staking.cairo` is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can call it with `disable_rewards: true` to advance the global `last_reward_block` without distributing rewards, causing the legitimate sequencer's subsequent call in the same block to revert with `REWARDS_ALREADY_UPDATED`. Repeated across every block, this permanently freezes unclaimed yield for all stakers.

### Finding Description
The protocol specification at `docs/spec.md` line 1645 states:

> **access control**: Only starkware sequencer.

However, the implementation of `update_rewards` in `src/staking/staking.cairo` contains no caller assertion:

```cairo
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
    // ... staker validity checks ...
    self.last_reward_block.write(current_block_number);   // <-- written unconditionally

    if disable_rewards || self.is_pre_consensus() {
        return;   // <-- returns without distributing rewards
    }
    // ... reward distribution ...
}
```

`last_reward_block` is a single global storage variable (not per-staker). Once it is written to `current_block_number`, no further call to `update_rewards` can succeed in the same block. An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` before the sequencer does will:

1. Pass the block-number guard.
2. Write `current_block_number` to `last_reward_block`.
3. Return early without distributing any rewards.

The sequencer's subsequent call with `disable_rewards: false` will then revert with `REWARDS_ALREADY_UPDATED`, and no rewards are distributed for that block.

The only precondition for the attacker is supplying a valid, active staker address — public information readable from on-chain events.

### Impact Explanation
Because `last_reward_block` is global, a single call per block is sufficient to block reward distribution for **all** stakers. An attacker who front-runs every block with `disable_rewards: true` causes stakers to accumulate zero rewards indefinitely. This matches the allowed HIGH impact: **Permanent freezing of unclaimed yield**.

### Likelihood Explanation
The Starknet sequencer controls intra-block transaction ordering, which limits opportunistic front-running. However:
- The sequencer may not call `update_rewards` in every block; any block it skips can be poisoned by the attacker.
- In a future decentralized or permissioned-sequencer model the attack becomes trivially reliable.
- The call costs only gas — no token deposit or privileged key is required.
- The attacker only needs one valid staker address, which is always available from public events.

Likelihood is **Medium** under the current centralized sequencer, escalating to **High** as the network decentralizes.

### Recommendation
Add an explicit caller check at the top of `update_rewards` to enforce the spec's "Only starkware sequencer" access control, for example by storing an authorized `rewards_manager` address during construction and asserting `get_caller_address() == self.rewards_manager.read()`.

### Proof of Concept
1. Attacker observes any active staker address `S` from on-chain events.
2. At each new block, attacker submits: `update_rewards(S, disable_rewards: true)`.
3. `last_reward_block` is set to the current block number; no rewards are distributed.
4. The legitimate sequencer calls `update_rewards(S, disable_rewards: false)` in the same block → reverts with `REWARDS_ALREADY_UPDATED`.
5. Stakers accumulate zero rewards for every block the attacker front-runs.

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2)

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
