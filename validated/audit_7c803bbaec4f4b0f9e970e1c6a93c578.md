### Title
Missing Sequencer-Only Access Control on `update_rewards` Allows Any Caller to Permanently Freeze Per-Block Staker Rewards — (`File: src/staking/staking.cairo`)

### Summary

The `update_rewards` function in the Staking contract is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can invoke it with `disable_rewards: true`, which advances `last_reward_block` to the current block without distributing any rewards. Because the contract enforces a strict one-call-per-block invariant (`REWARDS_ALREADY_UPDATED`), the legitimate sequencer is then blocked from distributing rewards for that block. Repeated across every block, this permanently freezes all staker and delegator unclaimed yield.

### Finding Description

The specification for `update_rewards` states:

> **access control**: Only starkware sequencer.

The implementation at `src/staking/staking.cairo` lines 1449–1488 is:

```cairo
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
    ...
    self.last_reward_block.write(current_block_number);   // ← written unconditionally

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← exits without distributing
    }
    ...
```

`general_prerequisites()` is a shared helper that only checks the pause flag. Every other caller-restricted function in the contract calls `get_caller_address()` explicitly after `general_prerequisites()` (e.g., `claim_rewards` at line 415, `unstake_intent` at line 436, `change_reward_address` at line 525). `update_rewards` has no such check.

The one-call-per-block guard at line 1454–1458 (`REWARDS_ALREADY_UPDATED`) means that once `last_reward_block` is set to the current block, no further call — including the legitimate sequencer's — can distribute rewards for that block.

### Impact Explanation

An attacker calls `update_rewards(any_active_staker, disable_rewards: true)` in any block before the sequencer does. The result:

1. `last_reward_block` is set to the current block number.
2. The function returns early without distributing any rewards.
3. The sequencer's subsequent call reverts with `REWARDS_ALREADY_UPDATED`.
4. All stakers and their delegators permanently lose that block's unclaimed yield.

Repeated every block, this freezes 100% of consensus-era staking rewards. The attack is cheap (one transaction per block on Starknet) and requires no special privileges.

**Impact**: High — Permanent freezing of unclaimed yield for stakers and delegators.

### Likelihood Explanation

Any address can submit a transaction on Starknet. The attacker only needs to submit `update_rewards(victim_staker, disable_rewards: true)` once per block. Because Starknet gas costs are low and the function requires no stake or deposit, the attack is economically viable. The attacker has no profit motive but can cause sustained, irreversible yield loss to all stakers.

### Recommendation

Add an explicit sequencer-only caller check at the top of `update_rewards`, consistent with the specification:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    ...
```

If the sequencer address is not stored on-chain, use Starknet's `get_sequencer_address()` syscall instead.

### Proof of Concept

1. Staker Alice stakes and becomes active after K epochs.
2. Consensus rewards are activated (`is_pre_consensus()` returns false).
3. In block N, attacker Bob calls:
   ```
   staking.update_rewards(staker_address: alice, disable_rewards: true)
   ```
4. `last_reward_block` is written to N; function returns without distributing rewards.
5. The sequencer attempts to call `update_rewards(alice, false)` in the same block → reverts with `REWARDS_ALREADY_UPDATED`.
6. Alice and her delegators receive zero rewards for block N.
7. Bob repeats step 3 in every subsequent block → Alice's unclaimed yield is permanently frozen. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L411-421)
```text
        fn claim_rewards(ref self: ContractState, staker_address: ContractAddress) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let caller_address = get_caller_address();
            let reward_address = staker_info.reward_address;
            assert!(
                caller_address == staker_address || caller_address == reward_address,
                "{}",
                Error::CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );
```

**File:** src/staking/staking.cairo (L1449-1490)
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
