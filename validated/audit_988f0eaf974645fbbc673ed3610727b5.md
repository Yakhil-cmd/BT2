### Title
Missing Caller Validation in `update_rewards()` Allows Anyone to Permanently Freeze Staker Yield - (File: src/staking/staking.cairo)

### Summary

`IStakingRewardsManager::update_rewards()` is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can call it with `disable_rewards: true` once per block, consuming the global `last_reward_block` slot without distributing rewards, and permanently blocking the legitimate sequencer from distributing block rewards to all stakers.

### Finding Description

The spec for `update_rewards` explicitly states:

> **access control**: Only starkware sequencer.

However, the implementation at `src/staking/staking.cairo` lines 1447–1507 contains no `get_caller_address()` assertion:

```rust
#[abi(embed_v0)]
impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
    fn update_rewards(
        ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
    ) {
        self.general_prerequisites();          // only checks pause state
        let current_block_number = starknet::get_block_number();
        assert!(
            current_block_number > self.last_reward_block.read(),
            "{}",
            Error::REWARDS_ALREADY_UPDATED,
        );
        // ...
        self.last_reward_block.write(current_block_number);  // global slot consumed

        if disable_rewards || self.is_pre_consensus() {
            return;   // exits without distributing any rewards
        }
        // ... reward distribution only reached if disable_rewards == false
    }
}
```

`last_reward_block` is a single global storage variable (not per-staker). Once it is written to the current block number, no further call to `update_rewards` can succeed for that block — for **any** staker — because the guard `current_block_number > self.last_reward_block.read()` will fail.

An attacker exploits this by:
1. Calling `update_rewards(any_valid_active_staker, disable_rewards: true)` at the start of every block.
2. The function writes `last_reward_block = current_block` and returns immediately without distributing rewards.
3. The sequencer's legitimate call with `disable_rewards: false` reverts with `REWARDS_ALREADY_UPDATED`.
4. All stakers receive zero block rewards for that block.

Repeating this every block permanently freezes all stakers' unclaimed yield.

### Impact Explanation

This is a **High** impact finding: **Permanent freezing of unclaimed yield**.

- All stakers and their delegation pool members lose all consensus-era block rewards indefinitely.
- The attacker has no profit motive but causes direct, measurable loss to every staker and delegator in the protocol.
- The attack is cheap (one transaction per block) and requires no special privileges.

### Likelihood Explanation

- The function is publicly callable with no access control.
- Any address can call it with a valid active staker address (which is publicly discoverable via `get_stakers()`).
- The cost is one transaction per block; a motivated griever can sustain this indefinitely.
- No preconditions beyond the staker being active and the contract being unpaused.

### Recommendation

Add a caller check at the top of `update_rewards` to enforce the spec's "Only starkware sequencer" access control:

```rust
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    self.general_prerequisites();
    // ...
}
```

Alternatively, if the sequencer address is not stored, use Starknet's `get_sequencer_address()` syscall.

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. Staker `S` is active with non-zero balance.
3. Attacker calls `update_rewards(S, disable_rewards: true)` at block `N`.
   - `last_reward_block` is written to `N`; no rewards distributed.
4. Sequencer calls `update_rewards(S, disable_rewards: false)` at block `N`.
   - Reverts: `REWARDS_ALREADY_UPDATED` (because `N > N` is false).
5. Staker `S` (and all other stakers) receive zero rewards for block `N`.
6. Attacker repeats step 3 at every subsequent block → permanent yield freeze. [1](#0-0) [2](#0-1) [3](#0-2)

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
