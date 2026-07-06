### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Block Consensus Reward Distribution - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in the Staking contract is documented to be callable only by the Starkware sequencer, but the implementation enforces no such restriction. Any unprivileged caller can invoke it with `disable_rewards=true`, which advances the global `last_reward_block` checkpoint without distributing any rewards. Because the contract enforces a strict "one call per block" invariant on this global variable, the sequencer's legitimate reward-distribution call for that block is permanently blocked. An attacker can repeat this every block to freeze all consensus reward accrual for all stakers indefinitely.

### Finding Description

`IStakingRewardsManager::update_rewards` is the sole mechanism for distributing per-block consensus rewards to stakers and their delegation pools. The spec explicitly restricts its caller:

> **access control**: Only starkware sequencer.
> (`docs/spec.md`, line 1645)

The implementation, however, only calls `self.general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero — no sequencer identity check is performed:

```rust
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();   // only: unpaused + caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ...
    self.last_reward_block.write(current_block_number);   // global write

    if disable_rewards || self.is_pre_consensus() {
        return;   // exits without distributing any rewards
    }
    // ... reward calculation and distribution
}
```

`last_reward_block` is a **single global storage slot** (not per-staker). Once it is written to block `N`, no further call to `update_rewards` can succeed in block `N` — for any staker — because the guard `current_block_number > self.last_reward_block.read()` will revert with `REWARDS_ALREADY_UPDATED`.

An attacker calls `update_rewards(any_valid_staker, disable_rewards=true)` in block `N`:
1. `last_reward_block` is advanced to `N`.
2. The function returns early — zero rewards are distributed.
3. The sequencer's subsequent call in block `N` reverts with `REWARDS_ALREADY_UPDATED`.
4. Block `N`'s rewards are permanently lost; they can never be reclaimed.

Repeating this every block completely halts consensus reward distribution for all stakers and delegators.

### Impact Explanation

Every block in which the attacker front-runs the sequencer, the entire block's worth of consensus rewards — for every staker and every delegation pool — is permanently frozen and unclaimable. The attacker can sustain this indefinitely at the cost of one transaction per block, causing **permanent freezing of unclaimed yield** for all protocol participants.

This matches the allowed High impact: *Permanent freezing of unclaimed yield or unclaimed royalties*.

### Likelihood Explanation

- The function is publicly callable with no role check.
- The attacker needs only a valid (non-zero) staker address as an argument, which is trivially obtained from on-chain events.
- The cost is one cheap transaction per block; no capital is required.
- The attack is fully permissionless and repeatable.

Likelihood: **High**.

### Recommendation

Enforce the access control stated in the spec. Add a sequencer-only guard at the top of `update_rewards`, analogous to the existing `assert_caller_is_attestation_contract` guard used in `update_rewards_from_attestation_contract`:

```rust
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer();   // add this
    // ...
}
```

Alternatively, if a dedicated sequencer role is not yet implemented, restrict the caller to the attestation contract or another trusted address, and document the invariant in the interface.

### Proof of Concept

1. Staker `S` is active and consensus rewards are live (`is_pre_consensus()` returns `false`).
2. Attacker observes the mempool / block production and, in block `N`, calls:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
3. `last_reward_block` is written to `N`; no rewards are distributed.
4. The sequencer attempts `staking.update_rewards(staker_address: S, disable_rewards: false)` in the same block `N` — it reverts with `REWARDS_ALREADY_UPDATED`.
5. Block `N`'s rewards are permanently lost.
6. The attacker repeats steps 2–5 every block. All stakers' `unclaimed_rewards_own` and all pool reward balances remain at zero indefinitely.

**Root cause lines:** [1](#0-0) 

**Spec access-control requirement (violated):** [2](#0-1) 

**Global `last_reward_block` write (blocks all subsequent callers in same block):** [3](#0-2) 

**Contrast: `update_rewards_from_attestation_contract` correctly enforces caller identity:** [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L1394-1401)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

**File:** src/staking/staking.cairo (L1449-1489)
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

**File:** docs/spec.md (L1644-1646)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```
