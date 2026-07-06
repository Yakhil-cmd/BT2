### Title
Missing Access Control on `update_rewards` Allows Anyone to Permanently Freeze Staker Yield - (`src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract is documented as callable only by the Starkware sequencer, but the implementation contains no access control check. Any unprivileged caller can invoke it with `disable_rewards: true` every block, consuming the global `last_reward_block` slot without distributing rewards, permanently denying all stakers their consensus-phase block rewards.

---

### Finding Description

`update_rewards` is the consensus-phase reward distribution entry point. The spec explicitly states:

> **access control**: Only starkware sequencer.

However, the implementation enforces no such restriction:

```rust
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();   // only checks pause state
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ...
    self.last_reward_block.write(current_block_number);  // global, not per-staker
    if disable_rewards || self.is_pre_consensus() {
        return;   // exits without distributing rewards
    }
    // ... reward distribution
``` [1](#0-0) 

The deduplication guard `last_reward_block` is a **single global variable** shared across all stakers. Once it is written to the current block number, no further call to `update_rewards` can succeed in that block for **any** staker. [2](#0-1) 

The spec confirms this is a global, per-block lock:

> **pre-condition**: Rewards did not distributed for the current block yet.
> **logic step 6**: Update `last_reward_block` to the current block. [3](#0-2) 

The `disable_rewards` flag, when `true`, causes the function to return immediately after writing `last_reward_block`, without distributing any rewards:

```rust
self.last_reward_block.write(current_block_number);
if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [4](#0-3) 

Contrast this with `update_rewards_from_attestation_contract`, which does enforce its caller restriction via `assert_caller_is_attestation_contract()`: [5](#0-4) 

`update_rewards` has no equivalent guard.

---

### Impact Explanation

An attacker calls `update_rewards(any_valid_staker_address, disable_rewards: true)` once per block. Each call:

1. Passes all checks (staker exists, has balance, block is new).
2. Writes `last_reward_block = current_block`.
3. Returns immediately without distributing rewards.
4. Blocks the legitimate sequencer from calling `update_rewards` for **any** staker in that block (`REWARDS_ALREADY_UPDATED`).

Repeated every block, this permanently freezes all consensus-phase block rewards for all stakers and their delegators. This maps to the allowed impact: **High — Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

- The function is publicly callable with no role check.
- The attacker only needs to know any valid active staker address (publicly readable from chain state).
- The cost is one transaction per block; on Starknet L2 this is negligible.
- No special knowledge, leaked keys, or privileged access is required.
- The attack is sustainable indefinitely.

---

### Recommendation

Add a sequencer-only access control check at the top of `update_rewards`, analogous to how `update_rewards_from_attestation_contract` checks `assert_caller_is_attestation_contract()`:

```rust
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer(); // add this
    // ...
```

Alternatively, if the sequencer address is not stored on-chain, restrict via an operator/app-governor role already present in the roles component.

---

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. Attacker identifies any valid staker address `S` with non-zero balance.
3. Each block, attacker submits:
   ```
   staking_contract.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. `last_reward_block` is set to the current block number; no rewards are distributed.
5. The sequencer's subsequent call to `update_rewards` for any staker in the same block reverts with `REWARDS_ALREADY_UPDATED`.
6. All stakers accumulate zero `unclaimed_rewards_own` indefinitely; delegators receive no pool rewards.

The flow test suite confirms the `REWARDS_ALREADY_UPDATED` guard fires on the second call in the same block, and that `disable_rewards: true` suppresses distribution while still consuming the block slot: [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L1397-1402)
```text
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
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

**File:** docs/spec.md (L1639-1652)
```markdown
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

**File:** src/flow_test/test.cairo (L2822-2844)
```text
    // Attempt again same block - panic
    let result = system
        .staking
        .rewards_manager_safe_dispatcher()
        .update_rewards(staker_address: staker.staker.address, disable_rewards: true);
    assert_panic_with_error(
        :result, expected_error: StakingError::REWARDS_ALREADY_UPDATED.describe(),
    );
    advance_block_number_global(blocks: 1);

    // Disable rewards = false with consensus off - no rewards
    system.update_rewards(:staker, disable_rewards: false);
    let rewards = system.staker_claim_rewards(:staker);
    assert!(rewards.is_zero());

    // Attempt again same block - panic
    let result = system
        .staking
        .rewards_manager_safe_dispatcher()
        .update_rewards(staker_address: staker.staker.address, disable_rewards: false);
    assert_panic_with_error(
        :result, expected_error: StakingError::REWARDS_ALREADY_UPDATED.describe(),
    );
```
