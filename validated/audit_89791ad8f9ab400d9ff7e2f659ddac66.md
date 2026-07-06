### Title
Unprivileged Caller Can Permanently Freeze Consensus Rewards via `update_rewards` — (File: `src/staking/staking.cairo`)

---

### Summary

`update_rewards` in `StakingRewardsManagerImpl` is documented to be callable only by the Starknet sequencer, but the implementation enforces no such restriction. Any non-zero address can call it with `disable_rewards: true`, consuming the single per-block reward slot without distributing rewards. Repeated across every block, this permanently freezes all stakers' unclaimed consensus yield.

---

### Finding Description

The `IStakingRewardsManager::update_rewards` function is the sole mechanism for distributing per-block consensus rewards to stakers and their pools. The protocol specification explicitly states:

> **Access control:** Only starkware sequencer.

However, the implementation only calls `general_prerequisites()`, which checks two things: the contract is not paused, and the caller is not the zero address. [1](#0-0) 

`general_prerequisites` itself: [2](#0-1) 

There is no `only_sequencer` role check, no allowlist, and no other caller restriction. The function then writes `current_block_number` to the global `last_reward_block` storage slot: [3](#0-2) 

Because `last_reward_block` is a single global value shared across all stakers, any call that successfully writes to it — regardless of whether rewards were distributed — blocks every subsequent call in the same block with `REWARDS_ALREADY_UPDATED`. An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` first in every block consumes the slot without distributing rewards, and the legitimate sequencer's call reverts.

The spec's access control requirement is confirmed in the documentation: [4](#0-3) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Once consensus rewards are active (`!is_pre_consensus()`), all staker and pool rewards are distributed exclusively through `update_rewards`. An attacker who front-runs the sequencer every block with `disable_rewards: true` prevents any rewards from ever being credited to `unclaimed_rewards_own` or forwarded to pool contracts. Stakers and delegators accumulate zero yield indefinitely. The attack requires no capital, no privileged role, and no external dependency — only the ability to submit a transaction before the sequencer in each block.

---

### Likelihood Explanation

**High.** The entry point is fully public (any non-zero address), requires no stake or special setup, and is cheap to call. On Starknet, a determined attacker can submit this transaction every block at negligible cost. The `REWARDS_ALREADY_UPDATED` guard means a single successful call per block is sufficient to block the sequencer.

---

### Recommendation

Add a caller restriction to `update_rewards` matching the documented access control. The simplest approach is to introduce a dedicated `REWARDS_MANAGER` role (analogous to the existing `SECURITY_AGENT` / `TOKEN_ADMIN` roles) and assert it at the top of the function:

```cairo
fn update_rewards(ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool) {
    self.roles.only_rewards_manager(); // new role check
    self.general_prerequisites();
    // ...
}
```

Alternatively, restrict the caller to the registered sequencer address stored in contract configuration.

---

### Proof of Concept

1. Consensus rewards are enabled (`consensus_rewards_first_epoch` has passed).
2. A valid staker `S` exists with non-zero balance at the current epoch.
3. Attacker (any non-zero EOA) calls:
   ```
   update_rewards(staker_address: S, disable_rewards: true)
   ```
   at the start of every block.
4. `last_reward_block` is set to the current block number.
5. The legitimate sequencer's call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
6. No staker receives any consensus rewards. `unclaimed_rewards_own` for all stakers remains zero indefinitely.

The existing test suite confirms that `update_rewards` is callable by any address without restriction: [5](#0-4) 

No `cheat_caller_address` to a privileged role is needed — the test calls the function directly from an unprivileged address and expects it to succeed (or fail only on business-logic conditions, never on access control).

### Citations

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

**File:** src/staking/staking.cairo (L1484-1488)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
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

**File:** src/staking/tests/test.cairo (L3841-3856)
```text
    let staking_dispatcher = IStakingDispatcher { contract_address: staking_contract };
    let staking_rewards_dispatcher = IStakingRewardsManagerDispatcher {
        contract_address: staking_contract,
    };
    let staking_rewards_safe_dispatcher = IStakingRewardsManagerSafeDispatcher {
        contract_address: staking_contract,
    };
    let staker_address = cfg.test_info.staker_address;

    // Catch STAKER_NOT_EXISTS.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::STAKER_NOT_EXISTS.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::STAKER_NOT_EXISTS.describe());
```
