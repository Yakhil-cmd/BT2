### Title
Missing Caller Access Control on `update_rewards` Allows Any Address to Block Reward Distribution - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in `StakingRewardsManagerImpl` is callable by any address, despite the protocol specification explicitly requiring "Only starkware sequencer" access. Because `last_reward_block` is a single global storage variable, any unprivileged caller can invoke `update_rewards` with `disable_rewards: true` once per block to consume the block's reward slot without distributing any rewards, permanently preventing the sequencer from distributing staker rewards.

### Finding Description
The protocol specification at `docs/spec.md` lines 1644–1645 states:

```
#### access control
Only starkware sequencer.
```

The implementation at `src/staking/staking.cairo` lines 1447–1508 enforces no such restriction. The only gate is `general_prerequisites()`, which at lines 1794–1797 only checks that the contract is unpaused and that the caller is not the zero address:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
```

No check of the form `get_caller_address() == sequencer_address` exists anywhere in `update_rewards`.

The function writes to the global `last_reward_block` storage variable at line 1485:

```cairo
self.last_reward_block.write(current_block_number);
```

This write happens unconditionally before the `disable_rewards` early-return at line 1487. Any caller who passes a valid, active staker address will advance `last_reward_block` to the current block, causing every subsequent call in the same block to revert with `REWARDS_ALREADY_UPDATED` (lines 1454–1458).

### Impact Explanation
An attacker calls `update_rewards(valid_staker, disable_rewards: true)` at the start of every block. This:
1. Passes all validity checks (staker exists, is active, has non-zero balance).
2. Writes `last_reward_block = current_block_number` — consuming the block's single reward slot.
3. Returns early without distributing any rewards.

The legitimate sequencer call for the same block then fails with `REWARDS_ALREADY_UPDATED`. Stakers and their delegation pools receive zero rewards for every block the attacker front-runs. Sustained over time this constitutes **permanent freezing of unclaimed yield**, matching the High impact tier.

### Likelihood Explanation
The attack requires no special privilege, no capital, and no leaked key — only the ability to submit a transaction before the sequencer's `update_rewards` call each block. Any valid staker address (public on-chain) suffices. The cost is one transaction per block. The attack is fully automatable and can be sustained indefinitely.

### Recommendation
Add a caller check at the top of `update_rewards` that asserts `get_caller_address()` equals the configured sequencer address, consistent with the access control specified in `docs/spec.md`. A dedicated storage variable holding the sequencer address (set at initialization) and a corresponding assertion should be introduced, mirroring the pattern already used for other privileged roles (e.g., `only_security_agent`, `only_token_admin`).

### Proof of Concept
```
// Any unprivileged address can call this once per block:
IStakingRewardsManagerDispatcher { contract_address: staking_contract }
    .update_rewards(staker_address: any_valid_staker, disable_rewards: true);

// Sequencer's legitimate call in the same block now reverts:
// panics with Error::REWARDS_ALREADY_UPDATED
IStakingRewardsManagerDispatcher { contract_address: staking_contract }
    .update_rewards(staker_address: any_valid_staker, disable_rewards: false);
```

The root cause is confirmed at:
- Spec access control requirement: [1](#0-0) 
- Missing check in implementation — only `general_prerequisites` is called: [2](#0-1) 
- `general_prerequisites` only checks pause and non-zero caller, no sequencer check: [3](#0-2) 
- Global `last_reward_block` written before the `disable_rewards` guard: [4](#0-3)

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

**File:** src/staking/staking.cairo (L1794-1797)
```text
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
