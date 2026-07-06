### Title
Anyone Can Call `update_rewards` With `disable_rewards: true`, Permanently Freezing Per-Block Yield - (File: `src/staking/staking.cairo`)

### Summary

`StakingRewardsManagerImpl::update_rewards` is callable by any address with no access control. The function accepts a caller-controlled `disable_rewards: bool` parameter. When set to `true`, the function writes the current block number to `last_reward_block` and returns early without distributing rewards. Because `last_reward_block` is already set, no subsequent caller can distribute rewards for that block. An attacker can call this once per block to permanently suppress all consensus-based yield for every staker.

### Finding Description

The spec at `docs/spec.md` lines 1644–1645 explicitly states:

> **access control**: Only starkware sequencer.

However, the implementation in `src/staking/staking.cairo` contains no such check. The function begins with only `general_prerequisites()` (a pause check) and a `REWARDS_ALREADY_UPDATED` guard: [1](#0-0) 

There is no `get_caller_address()` comparison against a sequencer address, no role check, and no other caller restriction. Any unprivileged address may call the function.

The `disable_rewards` parameter is accepted without validation. When `true`, the function unconditionally writes `current_block_number` to `last_reward_block` and returns before any reward calculation: [2](#0-1) 

Because `last_reward_block` is now equal to `current_block_number`, the guard at line 1454–1458 will revert for any subsequent call in the same block: [3](#0-2) 

The rewards for that block are permanently unrecoverable — there is no mechanism to retroactively distribute skipped block rewards.

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` once per block permanently destroys the consensus-based block reward for that block across all stakers and delegators. Repeated across every block, this completely halts yield accrual for the entire protocol. Stakers and pool members lose all consensus rewards indefinitely with no recovery path.

### Likelihood Explanation

**High.** The entry point is fully public, requires no tokens, no stake, and no privileged role. A single transaction per block suffices. The attacker has no cost beyond gas. The attack is trivially automatable with a simple bot that monitors the chain and front-runs the legitimate sequencer call each block.

### Recommendation

Add an access control check at the top of `update_rewards` that restricts the caller to the authorized sequencer address (or a designated role), consistent with the specification:

```cairo
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

Alternatively, store the sequencer address in a role managed by the existing `RolesComponent` and check it via `only_sequencer`.

### Proof of Concept

```cairo
// Any unprivileged address can call this once per block.
// After this call, no legitimate sequencer call can distribute rewards for this block.
fn attack(staking: IStakingRewardsManagerDispatcher, any_active_staker: ContractAddress) {
    // disable_rewards = true → last_reward_block is set, rewards are skipped.
    staking.update_rewards(staker_address: any_active_staker, disable_rewards: true);
    // Any subsequent call to update_rewards for this block reverts with REWARDS_ALREADY_UPDATED.
    // Block rewards are permanently lost.
}
```

The spec confirms the intended restriction: [4](#0-3) 

The implementation that lacks the check: [5](#0-4)

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
