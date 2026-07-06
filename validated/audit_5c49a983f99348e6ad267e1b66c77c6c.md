### Title
`IStakingRewardsManager::update_rewards` Lacks Caller Restriction, Enabling Permanent Yield Freeze for All Stakers — (`File: src/staking/staking.cairo`)

### Summary

`update_rewards` is documented as callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can call it with `disable_rewards: true` to consume the per-block `last_reward_block` slot without distributing rewards, permanently denying consensus-epoch yield to every staker for that block.

### Finding Description

The spec explicitly restricts `update_rewards` to the Starkware sequencer:

> **access control:** Only starkware sequencer.
> (`docs/spec.md:1644–1645`)

The implementation, however, performs no such check:

```cairo
// src/staking/staking.cairo:1448-1488
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks pause flag
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker existence checks ...
    self.last_reward_block.write(current_block_number);   // @audit global slot consumed

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // @audit returns with no rewards
    }
    // ... reward distribution only reached if caller did not pass disable_rewards: true
```

`last_reward_block` is a **global** (non-per-staker) storage variable. Writing it for any staker in a block prevents any further call to `update_rewards` in that same block for **all** stakers, because the guard `current_block_number > self.last_reward_block.read()` will revert with `REWARDS_ALREADY_UPDATED`.

Attack path:

1. Attacker identifies any valid, active staker address (all staker registrations are public via events / `staker_info_v1`).
2. In every block, attacker calls `update_rewards(valid_staker, disable_rewards: true)` before the sequencer's transaction is included.
3. `last_reward_block` is set to the current block number; the function returns early with no rewards distributed.
4. The sequencer's subsequent call reverts with `REWARDS_ALREADY_UPDATED`.
5. Consensus-epoch rewards for that block are permanently lost for every staker and every delegation pool.

### Impact Explanation

Every block in which the attacker front-runs the sequencer results in permanently lost consensus rewards for all stakers and their delegators. Repeated across many blocks, this constitutes **permanent freezing of unclaimed yield** for the entire protocol. This matches the allowed High impact: *"Permanent freezing of unclaimed yield or unclaimed royalties."*

### Likelihood Explanation

The function is `pub` with no caller restriction. On Starknet, transaction ordering within a block is determined by the sequencer, but the sequencer itself is the intended caller — meaning a malicious actor who submits a transaction in the same block can race it. The attacker needs only a valid staker address (trivially obtained from on-chain events) and enough gas to call the function once per block. No privileged access, leaked key, or external dependency is required.

### Recommendation

Add an explicit caller check matching the documented access control. The sequencer address should be stored at initialization and enforced:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
+   assert!(
+       get_caller_address() == self.sequencer_address.read(),
+       "{}",
+       Error::CALLER_IS_NOT_SEQUENCER,
+   );
    self.general_prerequisites();
    // ...
```

Alternatively, if the sequencer address is not stored, gate the function behind the existing `OPERATOR` role (already used elsewhere in the protocol) or a dedicated `SEQUENCER` role.

### Proof of Concept

```cairo
// Any unprivileged address can execute this in every block:
// 1. Find any active staker address (e.g., from NewStaker events).
// 2. Call update_rewards with disable_rewards: true before the sequencer.

let staking_rewards = IStakingRewardsManagerDispatcher { contract_address: staking_contract };

// Attacker calls first in the block — no access control stops them.
staking_rewards.update_rewards(staker_address: known_active_staker, disable_rewards: true);

// Sequencer's legitimate call now reverts:
// "REWARDS_ALREADY_UPDATED" because last_reward_block == current_block_number.
// Rewards for this block are permanently lost for all stakers.
```

**Root cause references:**
- Missing caller check: [1](#0-0) 
- Spec mandates sequencer-only access: [2](#0-1) 
- Global `last_reward_block` write that blocks all subsequent calls in the same block: [3](#0-2) 
- `IStakingRewardsManager` interface with no access-control annotation: [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L1448-1489)
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
