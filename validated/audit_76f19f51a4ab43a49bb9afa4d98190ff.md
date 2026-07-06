### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Deny Block Rewards - (File: `src/staking/staking.cairo`)

### Summary
The `update_rewards` function in `src/staking/staking.cairo` is specified in the protocol spec as callable by "Only starkware sequencer," but the implementation contains **no caller check whatsoever**. Any unprivileged address can call `update_rewards(staker_address, disable_rewards: true)`, which advances the global `last_reward_block` to the current block without distributing rewards. Because the guard `current_block_number > self.last_reward_block.read()` then fails for the rest of that block, the legitimate sequencer call with `disable_rewards: false` is permanently blocked, and all stakers lose their consensus block rewards for that block with no recovery path.

### Finding Description
`IStakingRewardsManager::update_rewards` is a public, permissionless entry point:

```
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
)
```

The spec at `docs/spec.md:1644-1645` explicitly states:
> **access control**: Only starkware sequencer.

The implementation at `src/staking/staking.cairo:1449-1507` performs only these checks:
1. `self.general_prerequisites()` — only verifies the contract is not paused.
2. `current_block_number > self.last_reward_block.read()` — prevents double-update within the same block.
3. Staker existence and activity checks.

There is **no check that `get_caller_address()` equals the sequencer**. The grep for any sequencer-related assertion (`CALLER_IS_NOT_SEQUENCER`, `only_sequencer`, etc.) returns zero matches across all source files.

The critical side-effect is at line 1485:
```cairo
self.last_reward_block.write(current_block_number);
```
This write happens unconditionally before the `disable_rewards` branch. An attacker calling with `disable_rewards: true` advances `last_reward_block` to the current block without distributing any rewards. The sequencer's subsequent call for the same block then hits `Error::REWARDS_ALREADY_UPDATED` and reverts. The rewards for that block are permanently lost — there is no mechanism to retroactively credit them.

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

`last_reward_block` is a single global storage variable shared across all stakers. A single call to `update_rewards(any_valid_active_staker, disable_rewards: true)` per block is sufficient to deny **all** stakers their consensus block rewards for that block. Because the block number can never be revisited, the lost yield is irrecoverable. Repeated across many blocks, this constitutes a sustained, low-cost denial of all consensus-phase staking rewards.

### Likelihood Explanation
**High.** The function is publicly callable with no authentication. The attacker needs only a valid active staker address (publicly readable from on-chain events) and enough gas to call the function once per block. No privileged access, no leaked keys, and no third-party dependency is required. The attack is cheap, repeatable, and entirely permissionless.

### Recommendation
Add a sequencer-only access control guard at the top of `update_rewards`, analogous to the pattern used in `update_rewards_from_attestation_contract` (which checks `get_caller_address() == self.attestation_contract.read()`). Store the authorized sequencer address in contract storage and assert it at the start of `update_rewards`:

```cairo
assert!(
    get_caller_address() == self.sequencer_address.read(),
    "{}",
    Error::CALLER_IS_NOT_SEQUENCER,
);
```

### Proof of Concept
1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. Attacker observes any valid, active staker address `S` on-chain.
3. At block `N`, before the sequencer submits its `update_rewards(S, false)` transaction, the attacker submits `update_rewards(S, true)`.
4. The call succeeds: `last_reward_block` is written to `N`; no rewards are distributed.
5. The sequencer's `update_rewards(S, false)` for block `N` reverts with `REWARDS_ALREADY_UPDATED`.
6. All stakers permanently lose their block `N` consensus rewards.
7. The attacker repeats this every block at negligible cost.

**Relevant code references:**

Spec mandates sequencer-only access: [1](#0-0) 

Implementation has no caller check — only a pause check and block-number guard: [2](#0-1) 

`last_reward_block` is written unconditionally before the `disable_rewards` branch: [3](#0-2) 

The interface declares the function with no access-control annotation: [4](#0-3)

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

**File:** src/staking/interface.cairo (L303-311)
```text
#[starknet::interface]
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```
