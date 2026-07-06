### Title
Unrestricted `update_rewards` Allows Anyone to Permanently Freeze Per-Block Staker Rewards - (File: `src/staking/staking.cairo`)

---

### Summary

`IStakingRewardsManager::update_rewards` is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can call it with `disable_rewards: true`, which writes the current block number to `last_reward_block` and returns early without distributing rewards. The legitimate sequencer call for that same block then reverts with `REWARDS_ALREADY_UPDATED`, permanently destroying the staker's (and their delegators') block rewards.

---

### Finding Description

The specification at `docs/spec.md` line 1645 states:

> **access control**: Only starkware sequencer.

The implementation in `src/staking/staking.cairo` at `StakingRewardsManagerImpl::update_rewards` (lines 1449–1507) enforces no such restriction. The only guards are:

1. `general_prerequisites()` — checks the contract is not paused.
2. `current_block_number > self.last_reward_block.read()` — reverts with `REWARDS_ALREADY_UPDATED` if already called this block.
3. Staker existence and activity checks.
4. Non-zero staker balance check.

Critically, `self.last_reward_block.write(current_block_number)` is executed at line 1485 **before** the `disable_rewards` branch at line 1487:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // line 1485

if disable_rewards || self.is_pre_consensus() {
    return;                                            // line 1488 — exits with NO rewards distributed
}
```

An attacker calls `update_rewards(any_valid_staker, disable_rewards: true)`. The function:
- Passes all checks (staker is valid, block is new).
- Stamps `last_reward_block = current_block_number`.
- Returns immediately without distributing any rewards.

When the legitimate sequencer subsequently calls `update_rewards` for the same block, the assertion `current_block_number > self.last_reward_block.read()` fails and the transaction reverts with `REWARDS_ALREADY_UPDATED`. The rewards for that block are permanently lost.

---

### Impact Explanation

**Permanent freezing of unclaimed yield** — matching the allowed High impact.

For every block in which the attacker front-runs the sequencer:
- The staker's `unclaimed_rewards_own` is never incremented.
- Pool rewards are never transferred to delegation pools.
- The `last_reward_block` slot is consumed, making it impossible for the sequencer to recover rewards for that block.

Because `last_reward_block` is a single global slot (not per-staker), one successful attacker call per block is sufficient to deny rewards to **all** stakers for that block. Sustained over many blocks, this constitutes a permanent, irrecoverable loss of yield for every staker and delegator in the protocol.

---

### Likelihood Explanation

- **No privilege required**: any externally-owned account can call `update_rewards`.
- **Cheap to execute**: a single transaction per block on Starknet (low gas cost).
- **Staker address is public**: emitted in `NewStaker` events; any valid staker address suffices to pass the staker-existence check.
- **Griefing is profitable-free but highly damaging**: the attacker spends only transaction fees to deny yield to all stakers indefinitely.

---

### Recommendation

Add a caller check at the top of `update_rewards` that asserts `get_caller_address()` equals the designated sequencer address (stored in contract storage, analogous to how `update_rewards_from_attestation_contract` asserts `CALLER_IS_NOT_ATTESTATION_CONTRACT`). For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.assert_caller_is_sequencer(); // <-- add this
    self.general_prerequisites();
    ...
}
```

Alternatively, move `self.last_reward_block.write(current_block_number)` to **after** the `disable_rewards` / `is_pre_consensus()` early-return so that a no-op call does not consume the block slot — but the access-control fix is the correct primary mitigation.

---

### Proof of Concept

1. Staker `S` is active with non-zero balance. Consensus rewards are live (`!is_pre_consensus()`).
2. At block `N`, attacker calls:
   ```
   staking_contract.update_rewards(staker_address: S, disable_rewards: true)
   ```
3. Inside `update_rewards`:
   - `general_prerequisites()` passes (not paused).
   - `block_number (N) > last_reward_block` passes (first call this block).
   - Staker `S` exists and is active — passes.
   - `last_reward_block` is written to `N`. [1](#0-0) 
   - `disable_rewards == true` → function returns with zero rewards distributed. [2](#0-1) 
4. Sequencer calls `update_rewards(S, disable_rewards: false)` for block `N`:
   - `block_number (N) > last_reward_block (N)` → **false** → reverts `REWARDS_ALREADY_UPDATED`. [3](#0-2) 
5. Staker `S` and all delegators receive **zero rewards** for block `N`. Repeating this every block permanently freezes all yield.

The spec mandates sequencer-only access but the implementation exposes the function to any caller with no restriction: [4](#0-3) [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L1453-1458)
```text
            let current_block_number = starknet::get_block_number();
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
                Error::REWARDS_ALREADY_UPDATED,
            );
```

**File:** src/staking/staking.cairo (L1484-1485)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);
```

**File:** src/staking/staking.cairo (L1487-1489)
```text
            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

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
