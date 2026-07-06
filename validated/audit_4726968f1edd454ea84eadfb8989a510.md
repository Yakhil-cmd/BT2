### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Freeze All Staker Rewards - (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract is specified to be callable only by the Starkware sequencer, but the implementation contains no such access control check. Any unprivileged caller can invoke it with `disable_rewards: true` to consume the per-block reward slot without distributing any rewards, permanently blocking the sequencer from distributing rewards for that block. Repeated across every block, this permanently freezes all unclaimed yield for all stakers.

---

### Finding Description

`update_rewards` in `StakingRewardsManagerImpl` accepts a caller-controlled `staker_address` and `disable_rewards` flag. It enforces a global once-per-block gate via `last_reward_block`:

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
    self.last_reward_block.write(current_block_number);   // <-- slot consumed here

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // <-- no rewards distributed
    }
    // ... distribute rewards
}
``` [1](#0-0) 

The only gate is `general_prerequisites()`, which checks only that the contract is unpaused and the caller is non-zero:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [2](#0-1) 

The protocol specification explicitly states the access control requirement:

> **access control**: Only starkware sequencer. [3](#0-2) 

No sequencer identity check exists anywhere in the implementation. Compare this to `update_rewards_from_attestation_contract`, which correctly enforces its caller restriction:

```cairo
self.assert_caller_is_attestation_contract();
``` [4](#0-3) 

The attack path requires only a valid, active `staker_address` (public on-chain information). The attacker calls `update_rewards(any_active_staker, disable_rewards: true)` before the sequencer each block. Because `last_reward_block` is a **global** variable (not per-staker), a single such call per block poisons the slot for all stakers simultaneously.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Once the attacker calls `update_rewards(..., disable_rewards: true)` for block N, `last_reward_block` is set to N. Any subsequent call by the legitimate sequencer for block N reverts with `REWARDS_ALREADY_UPDATED`. No rewards are distributed for that block. Repeated every block, this permanently prevents all consensus-phase staking rewards from ever accruing to any staker or delegation pool. Accumulated unclaimed yield is frozen indefinitely.

---

### Likelihood Explanation

**Medium.** In Starknet's current centralized sequencer model, the sequencer can order its own `update_rewards` call first in each block. However:

1. The spec explicitly mandates sequencer-only access, meaning the missing check is an unambiguous implementation defect.
2. As Starknet decentralizes, the sequencer loses the ability to censor or front-run this call, making the attack trivially executable.
3. The attacker requires no capital, no special role, and no privileged access — only knowledge of any active staker address (fully public).
4. The attack is gas-cheap and can be automated.

---

### Recommendation

Add a sequencer-only access control check to `update_rewards`, mirroring the pattern used in `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer(); // <-- add this
    // ...
}
```

Alternatively, restrict via a role stored in contract state (e.g., `roles.only_sequencer()`), consistent with the existing `RolesComponent` pattern used elsewhere in the contract.

---

### Proof of Concept

1. Consensus rewards are active (`!self.is_pre_consensus()`).
2. Attacker identifies any active staker address `S` (readable from on-chain state).
3. At block N, attacker submits `update_rewards(S, disable_rewards: true)`.
4. Execution path: `general_prerequisites()` passes → `last_reward_block` written to N → early return, zero rewards distributed.
5. Sequencer submits its own `update_rewards(S, disable_rewards: false)` for block N → reverts: `REWARDS_ALREADY_UPDATED`.
6. All stakers and pool members receive zero rewards for block N.
7. Attacker repeats step 3 every block → all staker `unclaimed_rewards_own` and pool reward balances remain permanently at zero. [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L1394-1402)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** docs/spec.md (L1643-1646)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```
