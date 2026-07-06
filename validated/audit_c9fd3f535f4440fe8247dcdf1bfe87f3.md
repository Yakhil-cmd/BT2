### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Freeze Staker Yield - (File: src/staking/staking.cairo)

### Summary

`IStakingRewardsManager::update_rewards` is documented in the protocol spec as callable only by the Starkware sequencer, but the implementation enforces no such restriction. Any unprivileged caller can invoke it with `disable_rewards: true`, consuming the single per-contract `last_reward_block` slot for the current block and permanently preventing the legitimate sequencer from distributing rewards for that block.

### Finding Description

The protocol specification at `docs/spec.md:1644-1645` states:

> **access control**: Only starkware sequencer.

The implementation at `src/staking/staking.cairo:1448-1507` is:

```cairo
impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
    fn update_rewards(
        ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
    ) {
        self.general_prerequisites();          // only: unpaused + non-zero caller
        let current_block_number = starknet::get_block_number();
        assert!(
            current_block_number > self.last_reward_block.read(),
            "{}",
            Error::REWARDS_ALREADY_UPDATED,
        );
        ...
        self.last_reward_block.write(current_block_number);

        if disable_rewards || self.is_pre_consensus() {
            return;   // ← exits without distributing any rewards
        }
        ...
    }
}
```

`general_prerequisites()` only asserts the contract is unpaused and the caller is non-zero:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
```

There is no check that `get_caller_address() == sequencer_address`. The storage variable `last_reward_block` is a single global slot (not per-staker). Once it is written to the current block number, the guard `current_block_number > self.last_reward_block.read()` will revert for every subsequent call in the same block with `REWARDS_ALREADY_UPDATED`.

An attacker can therefore:
1. At the start of every block, call `update_rewards(any_valid_staker, disable_rewards: true)`.
2. `last_reward_block` is set to the current block; the function returns early without distributing rewards.
3. The legitimate sequencer's call with `disable_rewards: false` reverts with `REWARDS_ALREADY_UPDATED`.
4. All stakers lose their block rewards permanently — those rewards are never re-queued.

### Impact Explanation

Each block's rewards that are skipped are permanently lost; the protocol has no mechanism to retroactively credit missed blocks. Sustained execution of this attack (one cheap call per block) causes **permanent freezing of unclaimed yield** for every staker and delegator in the protocol.

This maps directly to the allowed High impact: *"Permanent freezing of unclaimed yield or unclaimed royalties."*

### Likelihood Explanation

The entry point is a public, permissionless function on the main staking contract. No special role, token balance, or prior state is required — only a non-zero address and an unpaused contract. The cost per block is a single L2 transaction. The attack is trivially repeatable and requires no coordination or capital.

### Recommendation

Enforce the sequencer-only access control that the specification mandates. Store the authorized sequencer address in contract storage and add a check at the top of `update_rewards`:

```cairo
assert!(
    get_caller_address() == self.sequencer_address.read(),
    "{}",
    Error::CALLER_IS_NOT_SEQUENCER,
);
```

Alternatively, if the function is intentionally open to any caller, the `disable_rewards` parameter must be removed or its effect on `last_reward_block` must be separated from reward distribution so that a caller cannot consume the block slot without distributing rewards.

### Proof of Concept

1. Deploy the system in a post-consensus-rewards state with at least one active staker.
2. At block N, before the sequencer acts, call:
   ```
   staking.update_rewards(staker_address, disable_rewards: true)
   ```
   from any non-zero address.
3. Observe `last_reward_block` is now N.
4. The sequencer calls `update_rewards(staker_address, disable_rewards: false)` — it reverts with `REWARDS_ALREADY_UPDATED`.
5. Advance to block N+1 and repeat from step 2.
6. After K repetitions, `staker.unclaimed_rewards_own` has not increased despite K blocks of active staking. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L1448-1488)
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
```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** docs/spec.md (L1626-1645)
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
