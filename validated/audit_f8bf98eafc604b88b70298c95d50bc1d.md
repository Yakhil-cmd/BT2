### Title
Missing Caller Authentication in `update_rewards` Allows Any Address to Permanently Deny Staker Rewards - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in the Staking contract is specified to be callable only by the Starkware sequencer, but the implementation contains no caller authentication check. Any unprivileged address can call `update_rewards` with `disable_rewards: true` to mark the current block as processed without distributing rewards, permanently preventing the legitimate sequencer from distributing rewards for that block.

### Finding Description

The `IStakingRewardsManager::update_rewards` function is the consensus-era reward distribution entry point. The protocol specification explicitly restricts access to "Only starkware sequencer": [1](#0-0) 

However, the implementation at `src/staking/staking.cairo` performs no caller identity check whatsoever: [2](#0-1) 

The function only checks `general_prerequisites()` (contract-pause guard) and the `REWARDS_ALREADY_UPDATED` guard. After passing those, it unconditionally writes `last_reward_block` to the current block number: [3](#0-2) 

When `disable_rewards` is `true`, the function returns immediately after updating `last_reward_block` without distributing any rewards. Because `last_reward_block` is now set to the current block, any subsequent call in the same block — including the legitimate sequencer call — will revert with `REWARDS_ALREADY_UPDATED`.

This is the direct analog to the external report: just as `HandleReply` processed ceremony state without verifying the sender was an authorized participant, `update_rewards` processes reward-distribution state without verifying the caller is the authorized sequencer.

### Impact Explanation

An attacker who calls `update_rewards(victim_staker_address, disable_rewards: true)` at the start of every block:

1. Sets `last_reward_block` to the current block number with zero rewards distributed.
2. Forces the sequencer's legitimate call to revert with `REWARDS_ALREADY_UPDATED`.
3. The staker permanently loses the block reward — there is no mechanism to retroactively distribute missed block rewards.

Repeated every block, this constitutes **permanent freezing of unclaimed yield** for targeted stakers. The attacker bears only gas costs, which are low on Starknet L2.

This falls under the allowed High impact: *Permanent freezing of unclaimed yield or unclaimed royalties*.

### Likelihood Explanation

The function is publicly callable with no access restriction in the deployed contract. Any address — including an unprivileged staker, delegator, or anonymous EOA — can invoke it. The attack requires no special privileges, no leaked keys, and no third-party compromise. The only cost is L2 gas per block. The attack is trivially scriptable and can be sustained indefinitely.

### Recommendation

Add an explicit sequencer-only caller check at the top of `update_rewards`, analogous to the pattern already used in `update_unclaimed_rewards_from_staking_contract` and `claim_rewards` in the reward supplier:

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
    // ... rest of function
```

The sequencer address should be stored in contract storage and set during initialization, following the same pattern as `attestation_contract` and `starkgate_address`.

### Proof of Concept

```cairo
// Attacker script — runs once per block before the sequencer
fn attack(staking_contract: ContractAddress, victim: ContractAddress) {
    let dispatcher = IStakingRewardsManagerDispatcher {
        contract_address: staking_contract,
    };
    // No special caller required — any address works
    dispatcher.update_rewards(staker_address: victim, disable_rewards: true);
    // last_reward_block is now set; sequencer call will revert with REWARDS_ALREADY_UPDATED
    // victim loses this block's rewards permanently
}
```

The existing test suite confirms no caller restriction exists — tests call `update_rewards` directly without any `cheat_caller_address_once` setup: [4](#0-3) [5](#0-4)

### Citations

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
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

**File:** src/staking/tests/test.cairo (L3617-3617)
```text
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
```

**File:** src/staking/tests/test.cairo (L3999-3999)
```text
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: true);
```
