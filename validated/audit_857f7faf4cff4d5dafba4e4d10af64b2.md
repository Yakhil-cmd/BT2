### Title
Missing Access Control on `update_rewards` Allows Anyone to Permanently Deny Staker Block Rewards - (File: `src/staking/staking.cairo`)

### Summary
The `update_rewards` function in the `StakingRewardsManagerImpl` is callable by any address despite the specification explicitly requiring "Only starkware sequencer" access. An unprivileged attacker can front-run the legitimate sequencer call with `disable_rewards: true`, causing `last_reward_block` to be updated without distributing rewards. The sequencer's subsequent call for the same block then reverts with `REWARDS_ALREADY_UPDATED`, permanently destroying that block's yield for the targeted staker.

### Finding Description

The specification at `docs/spec.md` lines 1644–1645 states:

> **access control**: Only starkware sequencer.

However, the implementation in `src/staking/staking.cairo` at `StakingRewardsManagerImpl::update_rewards` (lines 1447–1507) performs no caller check whatsoever. The only guards are:

1. `self.general_prerequisites()` — checks the contract is not paused.
2. `current_block_number > self.last_reward_block.read()` — ensures one call per block.

There is no `assert!(get_caller_address() == sequencer, ...)` or equivalent role check.

The critical side-effect is at line 1485:

```cairo
self.last_reward_block.write(current_block_number);
```

This write happens **before** the `disable_rewards` branch at line 1487:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
```

So calling `update_rewards(victim, disable_rewards: true)` consumes the block's reward slot and returns without distributing anything. Any subsequent call in the same block — including the legitimate sequencer call with `disable_rewards: false` — reverts with `REWARDS_ALREADY_UPDATED`.

The interface definition at `src/staking/interface.cairo` lines 303–311 also carries no access-control annotation, confirming the check was never implemented.

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Each block's rewards are a one-time event gated by `last_reward_block`. Once the attacker consumes the slot with `disable_rewards: true`, the staker's rewards for that block are gone forever. The attacker can repeat this every block, continuously zeroing out a targeted staker's (and their delegators') yield at negligible cost (only gas).

### Likelihood Explanation

**High.** The function is public, requires no special role, and the attack requires only a single transaction per block. On Starknet, transaction ordering within a block is controlled by the sequencer, but the attacker can submit the griefing transaction at the start of any block. The attacker has no profit motive but can cause sustained, irreversible yield loss to any staker.

### Recommendation

Add a sequencer-only access control check at the top of `update_rewards`, consistent with the specification. For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.roles.only_sequencer(); // enforce spec: "Only starkware sequencer"
    self.general_prerequisites();
    ...
}
```

Alternatively, move the `last_reward_block.write` to after the `disable_rewards` guard so that a no-op call does not consume the block's reward slot.

### Proof of Concept

1. Consensus rewards are active; staker `S` has been staking for `K+` epochs.
2. Block `N` is produced. The sequencer prepares `update_rewards(S, disable_rewards: false)`.
3. Attacker submits `update_rewards(S, disable_rewards: true)` in the same block, ordered before the sequencer's tx.
4. Attacker's call passes all checks, writes `last_reward_block = N`, then returns early — no rewards distributed.
5. Sequencer's call hits `assert!(N > last_reward_block.read())` → `N > N` is false → reverts with `REWARDS_ALREADY_UPDATED`.
6. Staker `S` and all delegators in `S`'s pools receive zero rewards for block `N`.
7. Attacker repeats every block to permanently freeze all of `S`'s yield.

---

**Root cause references:**

Spec mandates sequencer-only access: [1](#0-0) 

Interface has no access control annotation: [2](#0-1) 

Implementation has no caller check: [3](#0-2) 

`last_reward_block` is written before the `disable_rewards` guard: [4](#0-3)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
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

**File:** src/staking/staking.cairo (L1447-1458)
```text
    #[abi(embed_v0)]
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
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
