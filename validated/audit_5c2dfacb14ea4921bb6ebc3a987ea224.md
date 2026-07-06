### Title
`update_rewards` Lacks Access Control, Allowing Any Caller to Monopolize Per-Block Reward Distribution - (File: src/staking/staking.cairo)

### Summary
`update_rewards` is documented as callable only by the Starkware sequencer, but the implementation enforces no such restriction. Because `last_reward_block` is a single global variable, only one call to `update_rewards` can succeed per block. Any staker can call it for themselves in every block, permanently locking out all other stakers from receiving their block rewards.

### Finding Description
`update_rewards` in `StakingRewardsManagerImpl` begins with `self.general_prerequisites()` (a pause check) and a global block-number guard, but no caller identity check:

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
    // ...
    self.last_reward_block.write(current_block_number);
    // ...
    self._update_rewards(:staker_address, ...);
}
```

`last_reward_block` is a single contract-wide storage slot:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
```

Once any caller writes `current_block_number` into `last_reward_block`, every subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`. The spec explicitly states the access control for this function is **"Only starkware sequencer"**, but no on-chain enforcement exists.

The intended design is that the sequencer calls `update_rewards` for each staker once per block. Because the global lock allows only one call per block, an attacker who is a registered staker can front-run the sequencer in every block by calling `update_rewards(attacker_staker, false)`. This:
1. Distributes the attacker's proportional block rewards to themselves.
2. Sets `last_reward_block = current_block`, causing every subsequent call in that block to revert.
3. All other stakers receive zero rewards for that block.

The missed rewards are not retroactively recoverable; they are permanently lost.

### Impact Explanation
Every block in which the attacker calls `update_rewards` first, all other stakers and their delegators permanently lose their block reward entitlement. Over time this constitutes a permanent, unbounded freezing of unclaimed yield for the rest of the staker set. The attacker pays only gas; the damage to other participants is proportional to the total stake they hold and the number of blocks the attack is sustained.

### Likelihood Explanation
`update_rewards` is a public entry point with no caller restriction. Any registered staker can execute this attack. The only cost is gas per block. On Starknet, where block times are short and gas costs are low, sustaining the attack is economically feasible. The attacker also has a direct incentive: by calling it for themselves every block they guarantee they never miss a block reward, while competitors do.

### Recommendation
Add an access-control check matching the spec. Either:
- Restrict the caller to a whitelisted sequencer address (role-based), or
- Require the caller to be the `staker_address` being rewarded, so no staker can block another staker's reward slot.

Additionally, consider making `last_reward_block` per-staker rather than global, so that one staker's reward update does not consume the global slot for all others.

### Proof of Concept
1. Attacker registers as a staker with minimum stake.
2. After `K` epochs (stake becomes effective), attacker submits a transaction calling `update_rewards(attacker_address, false)` at the start of every block.
3. Because `last_reward_block` is set to the current block number, the sequencer's subsequent calls for other stakers revert with `REWARDS_ALREADY_UPDATED`.
4. After `N` blocks, all other stakers have accumulated zero rewards; the attacker has accumulated `N × block_rewards × (attacker_stake / total_stake)`.

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
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
