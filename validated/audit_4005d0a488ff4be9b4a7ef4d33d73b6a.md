### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Freeze Staker Yield — (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the Staking contract is documented to be callable only by the "starkware sequencer" but has no access control enforcement. Any unprivileged caller can invoke it with `disable_rewards: true`, which unconditionally advances the global `last_reward_block` counter without distributing any rewards. Because `last_reward_block` is a single global variable, this blocks the legitimate sequencer from calling `update_rewards` for any staker in that block, permanently denying all stakers their earned yield for that block. Repeated execution across blocks constitutes a complete, permanent freeze of staker yield.

### Finding Description

`update_rewards_from_attestation_contract` (the pre-consensus rewards path) correctly enforces caller identity:

```cairo
fn update_rewards_from_attestation_contract(...) {
    self.general_prerequisites();
    assert!(self.is_pre_consensus(), ...);
    self.assert_caller_is_attestation_contract(); // ← access control present
``` [1](#0-0) 

By contrast, `update_rewards` (the consensus rewards path) only calls `general_prerequisites()`, which checks only that the contract is unpaused and the caller is non-zero:

```cairo
fn update_rewards(ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool) {
    self.general_prerequisites(); // only: not paused + caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(current_block_number > self.last_reward_block.read(), Error::REWARDS_ALREADY_UPDATED);
    ...
    // Update last block rewards — UNCONDITIONAL, before the disable_rewards check
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return; // exits without distributing rewards
    }
``` [2](#0-1) 

`last_reward_block` is a single global storage variable, not per-staker:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [3](#0-2) 

The spec explicitly states this function is restricted to the sequencer:

> "Only starkware sequencer" can call `update_rewards`.



**Attack path:**
1. Attacker calls `update_rewards(any_active_staker, disable_rewards: true)` at block N.
2. `last_reward_block` is set to N; no rewards are distributed.
3. The legitimate sequencer calls `update_rewards(target_staker, disable_rewards: false)` at block N → reverts with `REWARDS_ALREADY_UPDATED`.
4. All stakers lose their earned yield for block N.
5. Repeated every block → complete permanent freeze of all staker yield.

The `general_prerequisites` helper confirms no sequencer check exists:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [4](#0-3) 

### Impact Explanation
**High — Permanent freezing of unclaimed yield.** Stakers permanently lose rewards for every block in which the attacker front-runs the sequencer. Because `last_reward_block` is global, a single attacker call with any valid active staker address blocks reward distribution for all stakers in that block. Executed continuously, this constitutes a complete, irreversible freeze of all staker yield with no recovery path (the missed block rewards are never redistributed).

### Likelihood Explanation
**Medium.** The attacker requires no special privileges — only a non-zero address and an active staker address (publicly enumerable from the `stakers` vector). On Starknet the sequencer controls transaction ordering within a block, but the sequencer does not call `update_rewards` in every block unconditionally; there are blocks where the sequencer omits the call (e.g., pre-consensus, `disable_rewards` blocks), leaving a window for the attacker. The attack is cheap (a single transaction per block) and requires no capital.

### Recommendation
Add a sequencer-role check to `update_rewards`, mirroring the pattern used in `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer(); // add this check
    ...
}
```

Alternatively, store the authorized sequencer address in contract storage and assert `get_caller_address() == self.sequencer_address.read()` at the top of the function, consistent with how `attestation_contract` is enforced.

### Proof of Concept

```
// Setup: any active staker exists (staker_address)
// At block N, before the sequencer acts:

// Attacker (any address) calls:
staking_rewards_dispatcher.update_rewards(
    staker_address: any_active_staker,
    disable_rewards: true,   // no rewards distributed
);
// last_reward_block is now N; no yield credited to any staker.

// Sequencer then attempts:
staking_rewards_dispatcher.update_rewards(
    staker_address: target_staker,
    disable_rewards: false,
);
// → panics: "REWARDS_ALREADY_UPDATED"
// target_staker's unclaimed_rewards_own is never incremented for block N.
// Repeating this every block permanently freezes all staker yield.
```

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
