### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Freeze Staker Consensus Rewards - (File: src/staking/staking.cairo)

### Summary
The `IStakingRewardsManager::update_rewards` function in the Staking contract is documented in the protocol spec as callable by "Only starkware sequencer," but the on-chain implementation enforces no such restriction. Any unprivileged address can call this function with `disable_rewards: true`, consuming the global `last_reward_block` slot for the current block and preventing the sequencer from distributing consensus rewards to any staker in that block. Repeated across blocks, this permanently freezes all staker unclaimed yield.

### Finding Description
The `update_rewards` function at `src/staking/staking.cairo:1449` is the sole mechanism for distributing per-block consensus rewards to stakers. Its access control in the spec reads:

> **Access control: Only starkware sequencer.**

However, the implementation contains no caller check:

```rust
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks pause
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker existence checks ...
    self.last_reward_block.write(current_block_number);   // global slot consumed here

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // no rewards distributed
    }
    // ... reward distribution ...
}
```

The critical design property is that `last_reward_block` is a **global** (not per-staker) storage variable. Exactly one successful call to `update_rewards` is permitted per block for the entire contract. Once any caller sets `last_reward_block = current_block`, every subsequent call in that block reverts with `REWARDS_ALREADY_UPDATED`.

An attacker exploits this by calling `update_rewards(any_valid_staker, disable_rewards: true)` before the sequencer in any block. The call:
1. Passes all checks (staker exists, block is new).
2. Writes `last_reward_block = current_block`.
3. Returns immediately without distributing rewards because `disable_rewards = true`.

The sequencer's subsequent call for the same block then reverts. No staker earns rewards for that block. Repeating this every block permanently freezes all consensus-era unclaimed yield.

The absence of any access control is confirmed by the unit test `test_update_rewards_only_staker` at `src/staking/tests/test.cairo:3487`, which calls `update_rewards` from the default (non-sequencer) test address with no `cheat_caller_address` and succeeds.

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

Once consensus rewards are active (`!is_pre_consensus()`), stakers earn per-block rewards via `update_rewards`. An attacker who front-runs the sequencer every block ensures `last_reward_block` is always consumed with `disable_rewards: true`. No staker ever accumulates `unclaimed_rewards_own` from consensus rewards. The funds are not stolen but are permanently withheld from all stakers and delegators, matching the "Permanent freezing of unclaimed yield" impact category.

### Likelihood Explanation
**Medium.**

The attack requires the attacker's transaction to be ordered before the sequencer's `update_rewards` call in each block. In Starknet's current centralized sequencer model, the sequencer controls ordering and would normally place its own call first. However:

1. The sequencer may not call `update_rewards` in every block (e.g., if no staker is selected, or due to operational gaps).
2. As Starknet moves toward decentralization, transaction ordering becomes less controlled, making front-running trivially achievable.
3. The complete absence of on-chain access control means the attack surface is permanently open; any future sequencer model change immediately enables full exploitation.
4. The attacker requires no capital, no privileged keys, and no special role — only the ability to submit transactions.

### Recommendation
Add an explicit on-chain caller check matching the spec's stated access control. The sequencer's address should be stored in contract configuration and enforced:

```rust
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_sequencer();   // add this check
    // ...
}
```

Alternatively, if the sequencer address is not known at deploy time, use a role-based check (e.g., a `SEQUENCER_ROLE`) that can be set by the governance admin, consistent with the existing `RolesComponent` pattern used throughout the contract.

### Proof of Concept

**Setup**: Consensus rewards are active (`!is_pre_consensus()`). The sequencer is expected to call `update_rewards(staker_A, disable_rewards: false)` in block N to distribute rewards.

**Attack**:
1. Attacker monitors for block N.
2. Attacker submits `update_rewards(staker_A, disable_rewards: true)` with sufficient priority to be included before the sequencer's call.
3. Attacker's call succeeds: `last_reward_block` is set to N, no rewards distributed.
4. Sequencer's call reverts with `REWARDS_ALREADY_UPDATED`.
5. Attacker repeats in block N+1, N+2, … indefinitely.

**Result**: `staker_A.unclaimed_rewards_own` remains zero forever. All stakers are affected because `last_reward_block` is global — one attacker call per block blocks all stakers.

**Confirming code references**:

- No access control in implementation: [1](#0-0) 
- Global `last_reward_block` write that blocks all subsequent calls: [2](#0-1) 
- Spec mandates "Only starkware sequencer": [3](#0-2) 
- Test confirms no caller restriction (called from default address, no cheat): [4](#0-3)

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

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

**File:** docs/spec.md (L1643-1646)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```

**File:** src/staking/tests/test.cairo (L3514-3516)
```text
    let mut spy = snforge_std::spy_events();
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    let staker_info_after = staking_dispatcher.staker_info_v1(:staker_address);
```
