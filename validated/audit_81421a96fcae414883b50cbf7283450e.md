### Title
Missing Caller Restriction on `update_rewards` Allows Anyone to Permanently Freeze Staker Rewards - (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in `IStakingRewardsManager` is documented in the spec as callable only by the Starkware sequencer, but the implementation contains no such access control check. Any unprivileged caller can invoke it with `disable_rewards: true` to consume the global `last_reward_block` slot for the current block without distributing rewards, permanently preventing the legitimate sequencer from distributing rewards for that block.

---

### Finding Description

The spec at `docs/spec.md` line 1644–1645 explicitly states:

> **access control**: Only starkware sequencer.

However, the implementation of `update_rewards` in `src/staking/staking.cairo` only calls `general_prerequisites()`, which checks two things: that the contract is not paused, and that the caller is not the zero address. [1](#0-0) 

The `general_prerequisites` helper: [2](#0-1) 

There is no `assert_caller_is_sequencer()` or equivalent check. The function is callable by any non-zero address.

The critical state mutation is: [3](#0-2) 

`last_reward_block` is a **single global** storage slot. Once it is written with the current block number, the guard `current_block_number > self.last_reward_block.read()` will fail for any subsequent call in the same block, including the legitimate sequencer's call. [4](#0-3) 

---

### Impact Explanation

An attacker calls `update_rewards(staker_address: any_active_staker, disable_rewards: true)` before the sequencer in any block where consensus rewards are active. This:

1. Writes `last_reward_block = current_block_number` (line 1485).
2. Returns early at the `disable_rewards || self.is_pre_consensus()` branch without distributing any rewards. [5](#0-4) 

When the sequencer subsequently attempts to call `update_rewards` in the same block, it reverts with `REWARDS_ALREADY_UPDATED`. The rewards for that block are permanently lost — there is no mechanism to retroactively distribute skipped blocks.

**Impact category**: Permanent freezing of unclaimed yield (High). Repeated across every block, this completely halts consensus reward accrual for all stakers and their delegators.

---

### Likelihood Explanation

- The function is publicly callable with no role restriction.
- The attacker only needs to know any active staker address (trivially obtained from on-chain events such as `NewStaker`).
- The only cost is gas per block. No capital is required.
- The attack is repeatable every block indefinitely.
- Front-running the sequencer on Starknet is feasible since transaction ordering within a block is controlled by the sequencer, but the attacker can submit the transaction in the same block before the sequencer's own `update_rewards` transaction is included.

---

### Recommendation

Add a caller restriction to `update_rewards` matching the spec's stated access control. The simplest fix is to add a role check at the top of the function, analogous to how `pause` and `set_min_stake` are protected: [6](#0-5) [7](#0-6) 

Specifically, `update_rewards` should assert `get_caller_address() == sequencer_address` (stored in contract storage), or use an appropriate role such as `only_operator` / `only_app_role_admin`, consistent with the existing `RolesComponent` pattern already used throughout the contract. [8](#0-7) 

---

### Proof of Concept

```
// Any unprivileged address can execute this every block:
// 1. Observe that block N is the current block.
// 2. Call: staking_contract.update_rewards(
//        staker_address: <any_active_staker>,
//        disable_rewards: true
//    )
//    → last_reward_block is set to N, no rewards distributed.
// 3. Sequencer attempts: staking_contract.update_rewards(
//        staker_address: <staker>,
//        disable_rewards: false
//    )
//    → Reverts with REWARDS_ALREADY_UPDATED (N > N is false).
// 4. Block N's rewards are permanently lost.
// 5. Repeat every block.
```

The spec confirms the intended restriction: [9](#0-8) 

The implementation omits it entirely: [10](#0-9)

### Citations

**File:** src/staking/staking.cairo (L84-87)
```text
    component!(path: ReplaceabilityComponent, storage: replaceability, event: ReplaceabilityEvent);
    component!(path: RolesComponent, storage: roles, event: RolesEvent);
    component!(path: AccessControlComponent, storage: accesscontrol, event: AccessControlEvent);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);
```

**File:** src/staking/staking.cairo (L1250-1252)
```text
        fn pause(ref self: ContractState) {
            self.roles.only_security_agent();
            if self.is_paused() {
```

**File:** src/staking/staking.cairo (L1271-1273)
```text
        fn set_min_stake(ref self: ContractState, min_stake: Amount) {
            self.roles.only_token_admin();
            let old_min_stake = self.min_stake.read();
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
