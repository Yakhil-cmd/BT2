### Title
Missing Caller Guard on `update_rewards` Allows Any Address to Permanently Suppress Block Rewards — (`src/staking/staking.cairo`)

---

### Summary

`update_rewards` is specified as "Only starkware sequencer" but the production implementation contains **no caller check**. Any unprivileged address can call it with `disable_rewards = true` every block, consuming the global `last_reward_block` gate and permanently discarding that block's rewards for every staker in the protocol.

---

### Finding Description

The spec explicitly restricts `update_rewards` to the Starkware sequencer:

> **access control**: Only starkware sequencer. [1](#0-0) 

The production implementation, however, contains no such check. After `general_prerequisites()` (which only checks pause state), the function immediately reads `last_reward_block` and proceeds: [2](#0-1) 

`last_reward_block` is a **single global** storage variable shared across all stakers: [3](#0-2) 

After validating the staker, the function unconditionally writes the current block number to `last_reward_block` **before** checking `disable_rewards`: [4](#0-3) 

When `disable_rewards = true`, the function returns immediately after writing `last_reward_block`, distributing zero rewards. Any subsequent call in the same block — including a legitimate sequencer call — reverts with `REWARDS_ALREADY_UPDATED`. [5](#0-4) 

---

### Impact Explanation

An attacker calls `update_rewards(any_valid_staker_address, disable_rewards: true)` once per block. Each call:

1. Passes all validation (staker exists, is active, has non-zero balance).
2. Writes `current_block_number` to the global `last_reward_block`.
3. Returns without distributing rewards to anyone.
4. Blocks every other caller for that block with `REWARDS_ALREADY_UPDATED`.

Repeated every block, this permanently freezes all consensus-era block rewards for all stakers and their delegators. The attacker needs no stake, no funds, and no privileged role — only gas.

**Impact**: Permanent freezing of unclaimed yield (High).

---

### Likelihood Explanation

The function is publicly callable on-chain with no economic barrier. A single EOA with enough gas to submit one transaction per block can execute this indefinitely. The attack is cheap, requires no setup, and is immediately executable after consensus rewards are activated.

---

### Recommendation

Add a sequencer-only caller check at the top of `update_rewards`, consistent with the spec. For example:

```rust
fn update_rewards(...) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    // ... rest of function
}
```

Alternatively, if the intended design is that the sequencer is identified by Starknet's built-in `get_sequencer_address()` syscall, use that directly without storing it.

---

### Proof of Concept

```
// Block N:
// Attacker (any address) calls:
staking.update_rewards(staker_address: any_valid_staker, disable_rewards: true);
// → last_reward_block = N, zero rewards distributed

// Sequencer (legitimate) tries in same block N:
staking.update_rewards(staker_address: validator_A, disable_rewards: false);
// → PANICS: REWARDS_ALREADY_UPDATED

// Repeat every block → all consensus block rewards permanently suppressed
```

The `REWARDS_ALREADY_UPDATED` guard at line 1454–1458 enforces exactly one call per block globally. Because `last_reward_block` is written before the `disable_rewards` branch at line 1485, a hostile call with `disable_rewards = true` irrevocably consumes the slot. [4](#0-3)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L186-187)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
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
