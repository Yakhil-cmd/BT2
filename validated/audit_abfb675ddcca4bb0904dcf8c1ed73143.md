### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Block Consensus Reward Distribution - (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in `src/staking/staking.cairo` is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can call it with `disable_rewards: true` to advance the global `last_reward_block` storage variable without distributing rewards. Because the function enforces a per-block uniqueness guard (`current_block_number > last_reward_block`), a griever who front-runs every block permanently prevents the sequencer from distributing consensus rewards to all stakers.

---

### Finding Description

The specification at `docs/spec.md` lines 1626–1652 explicitly states:

> **access control**: Only starkware sequencer.

The implementation at `src/staking/staking.cairo` lines 1447–1507 (`StakingRewardsManagerImpl::update_rewards`) performs no such check. The function body only calls:

1. `self.general_prerequisites()` — checks the contract is not paused.
2. `assert!(current_block_number > self.last_reward_block.read(), …, Error::REWARDS_ALREADY_UPDATED)` — ensures one call per block.
3. Staker existence / activity checks.
4. **Unconditionally** writes `self.last_reward_block.write(current_block_number)` at line 1485.
5. Returns early if `disable_rewards || self.is_pre_consensus()`.

There is no `assert!(get_caller_address() == sequencer, …)` or equivalent guard anywhere in the function. The `IStakingRewardsManager` interface definition at `src/staking/interface.cairo` lines 303–311 also carries no access-control annotation.

Compare with `update_rewards_from_attestation_contract` (lines 1394–1423), which correctly enforces `self.assert_caller_is_attestation_contract()` before proceeding.

**Attack path:**

1. Attacker monitors the mempool / block production.
2. At the start of every new block (or via a loop contract), attacker calls `update_rewards(staker_address: <any_valid_active_staker>, disable_rewards: true)`.
3. The call passes all checks (staker is valid, block is new) and writes `last_reward_block = current_block_number` without distributing any rewards.
4. When the sequencer subsequently calls `update_rewards` for the same block, the assertion `current_block_number > last_reward_block` fails with `REWARDS_ALREADY_UPDATED`, and no rewards are distributed.
5. Repeating this every block permanently freezes all consensus-phase reward accrual for every staker.

---

### Impact Explanation

During the consensus rewards phase (`!is_pre_consensus()`), `update_rewards` is the sole mechanism by which stakers accumulate `unclaimed_rewards_own` and pools receive their share. Blocking it indefinitely means:

- Stakers never receive block rewards; `unclaimed_rewards_own` is never incremented.
- Pool members never receive delegated rewards.
- All accrued yield is permanently frozen — no staker or delegator can claim rewards that were never credited.

This matches the allowed impact: **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

The attack requires no capital, no privileged role, and no external dependency. Any EOA or contract can call `update_rewards` on Starknet. The only cost is the gas for one transaction per block. The attack is fully permissionless and can be automated trivially. Likelihood is **High**.

---

### Recommendation

Add a sequencer-only access check at the top of `update_rewards`, mirroring the pattern used in `update_rewards_from_attestation_contract`:

```rust
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
}
```

Alternatively, restrict via the existing roles system (e.g., `self.roles.only_operator()`), consistent with how other privileged functions are guarded.

---

### Proof of Concept

```
// Attacker contract (pseudocode)
fn grief_rewards(staking: ContractAddress, valid_staker: ContractAddress) {
    // Called once per block, e.g. via a loop or external trigger
    IStakingRewardsManagerDispatcher { contract_address: staking }
        .update_rewards(staker_address: valid_staker, disable_rewards: true);
    // last_reward_block is now set to current block.
    // Sequencer's subsequent call reverts with REWARDS_ALREADY_UPDATED.
    // No staker receives consensus block rewards for this block.
}
```

**Relevant code locations:**

- Spec access-control requirement: [1](#0-0) 
- Missing caller check in implementation: [2](#0-1) 
- Unconditional `last_reward_block` write before early return: [3](#0-2) 
- Interface definition (no access-control annotation): [4](#0-3) 
- Correct pattern used in `update_rewards_from_attestation_contract`: [5](#0-4)

### Citations

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1397-1401)
```text
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
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
