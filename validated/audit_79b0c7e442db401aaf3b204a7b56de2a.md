### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Freeze Unclaimed Yield - (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract is specified to be callable only by the Starkware sequencer, but the implementation contains no such access control check. Any unprivileged address can call it with `disable_rewards: true` to consume the global `last_reward_block` slot for the current block, preventing the legitimate sequencer call from succeeding. Repeated across every block, this permanently freezes unclaimed yield for all stakers and delegators.

---

### Finding Description

The protocol specification explicitly states:

> **access control**: Only starkware sequencer. [1](#0-0) 

However, the implementation of `update_rewards` in `StakingRewardsManagerImpl` performs no caller identity check. The only gate is `general_prerequisites()`, which only asserts the contract is not paused, and a per-block guard on `last_reward_block`: [2](#0-1) 

Critically, `last_reward_block` is written to storage **before** the `disable_rewards` branch is evaluated: [3](#0-2) 

This means an attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` in a given block will:
1. Pass all checks (contract unpaused, block is new, staker is active).
2. Commit `last_reward_block = current_block_number` to storage.
3. Return immediately without distributing any rewards.

Any subsequent call in the same block — including the legitimate sequencer call — reverts with `REWARDS_ALREADY_UPDATED`. Because `last_reward_block` is a single global variable (not per-staker), one attacker call per block blocks reward distribution for **all** stakers. [4](#0-3) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Stakers and delegators accumulate rewards only when `update_rewards` is called with `disable_rewards: false` and consensus rewards are active. If an attacker front-runs the sequencer on every block with `disable_rewards: true`, no rewards are ever distributed. All stakers' `unclaimed_rewards_own` and all pool balances stop growing indefinitely. The attack is sustained as long as the attacker continues to pay gas per block.

---

### Likelihood Explanation

**Medium.** The attack requires no special role, no token balance beyond gas, and no coordination. Any address that knows a single valid active staker address (trivially discoverable from on-chain events) can execute it. The only cost is one Starknet transaction per block. A motivated griever (e.g., a competing protocol, a staker who was slashed, or a short-seller) has clear incentive. The attack is also detectable but not automatically stoppable without a contract upgrade or pause.

---

### Recommendation

Add a caller restriction to `update_rewards` matching the specification. The simplest fix is to assert that `get_caller_address()` equals the configured sequencer address (or a dedicated role), analogous to how `update_current_epoch_block_rewards` in the `RewardSupplier` restricts callers to the staking contract: [5](#0-4) 

Alternatively, introduce a `SEQUENCER_ROLE` and gate `update_rewards` behind `self.roles.only_sequencer()`.

---

### Proof of Concept

```
// Attacker script (pseudocode, run once per block):
//
// Prerequisites:
//   - `staker_A` is any known active staker address (readable from NewStaker events).
//   - Consensus rewards are active (post `consensus_rewards_first_epoch`).
//
// Step 1: Attacker calls update_rewards before the sequencer in every block.
IStakingRewardsManager(staking_contract)
    .update_rewards(staker_address: staker_A, disable_rewards: true);
//
// Result:
//   - `last_reward_block` is set to the current block number.
//   - No rewards are computed or distributed (early return).
//
// Step 2: Sequencer attempts its legitimate call in the same block.
IStakingRewardsManager(staking_contract)
    .update_rewards(staker_address: staker_A, disable_rewards: false);
// => PANICS with Error::REWARDS_ALREADY_UPDATED
//
// All stakers' `unclaimed_rewards_own` and pool balances remain frozen.
// Repeating this every block permanently halts yield accrual.
```

The `last_reward_block` write at line 1485 is the root cause — it is unconditional and precedes the `disable_rewards` guard at line 1487, making the slot consumable by any caller with no reward side-effect. [3](#0-2)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1449-1458)
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
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

**File:** src/reward_supplier/reward_supplier.cairo (L166-172)
```text
        fn update_current_epoch_block_rewards(ref self: ContractState) -> (Amount, Amount) {
            let staking_contract = self.staking_contract.read();
            assert!(
                get_caller_address() == staking_contract,
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );
```
