### Title
Unrestricted `update_rewards()` Allows Any Caller to Permanently Freeze Staker Yield - (File: `src/staking/staking.cairo`)

### Summary
`IStakingRewardsManager::update_rewards()` is specified as callable only by the Starkware sequencer, but the implementation contains no access-control check. Any unprivileged address can call it with `disable_rewards: true`, which writes `last_reward_block` to the current block before the early-return guard, permanently preventing the legitimate sequencer from distributing rewards for that block.

### Finding Description
The spec at `docs/spec.md` lines 1644–1645 states:

> **access control**: Only starkware sequencer.

The implementation at `src/staking/staking.cairo` lines 1447–1507 enforces no such restriction. The only guards are `general_prerequisites()` (pause check) and a block-number monotonicity check:

```
assert!(current_block_number > self.last_reward_block.read(), …REWARDS_ALREADY_UPDATED);
```

Critically, `last_reward_block` is written **unconditionally** at line 1485, *before* the `disable_rewards` branch at line 1487:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // line 1485

if disable_rewards || self.is_pre_consensus() {
    return;                                            // line 1488 – no rewards distributed
}
```

`last_reward_block` is a single global storage slot shared across all stakers. Once it is set to the current block, no further call to `update_rewards` can succeed in the same block (the `REWARDS_ALREADY_UPDATED` assertion fires). Because Starknet blocks are final, the missed distribution cannot be recovered.

### Impact Explanation
An attacker calls `update_rewards(any_valid_staker, disable_rewards: true)` once per block. This:
1. Passes all guards (contract not paused, block number is new).
2. Writes `last_reward_block = current_block`.
3. Returns without distributing any rewards.
4. Causes every subsequent call in that block—including the sequencer's legitimate call—to revert with `REWARDS_ALREADY_UPDATED`.

Rewards for that block are permanently lost for all stakers and delegators. Repeated across blocks, this constitutes **permanent freezing of unclaimed yield** for the entire protocol.

**Allowed impact matched**: *Permanent freezing of unclaimed yield or unclaimed royalties* (High).

### Likelihood Explanation
- No privileged role, no token, no stake required.
- The call is cheap (one storage read + one storage write before the early return).
- The attacker can automate it to fire on every new block.
- There is no economic cost to the attacker and no on-chain mechanism to prevent or undo it.

### Recommendation
Add a caller check at the top of `update_rewards` that restricts execution to the authorised sequencer address, consistent with the specification. For example:

```cairo
fn update_rewards(ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool) {
    self.roles.only_operator();   // or a dedicated sequencer role
    …
}
```

Alternatively, move the `self.last_reward_block.write(current_block_number)` assignment to *after* the `disable_rewards` guard so that a no-op call does not consume the block's reward slot.

### Proof of Concept
1. Deploy the system (consensus rewards active, staker registered with balance).
2. Advance to a new block.
3. Call `IStakingRewardsManagerDispatcher { contract_address: staking }.update_rewards(staker_address, disable_rewards: true)` from any EOA.
4. Observe `last_reward_block` is now equal to the current block number.
5. The sequencer (or anyone else) attempts `update_rewards(staker_address, disable_rewards: false)` in the same block → reverts with `REWARDS_ALREADY_UPDATED`.
6. Staker's `unclaimed_rewards_own` is unchanged; rewards for the block are gone.

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/staking/staking.cairo (L1447-1507)
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
```

**File:** docs/spec.md (L1626-1646)
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
