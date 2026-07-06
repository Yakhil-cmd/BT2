### Title
Missing Caller Validation in `update_rewards` Allows Any Address to Grief Consensus Rewards — (`File: src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the `Staking` contract is specified to be callable only by the Starkware sequencer, but the implementation contains no such access-control check. Any unprivileged address can call `update_rewards(staker_address, disable_rewards: true)` once per block to consume the global `last_reward_block` slot, permanently preventing the legitimate sequencer from distributing consensus rewards to any staker.

---

### Finding Description

The spec at `docs/spec.md` line 1645 states:

> **access control**: Only starkware sequencer.

However, the implementation of `update_rewards` in `src/staking/staking.cairo` (lines 1449–1507) performs no caller identity check whatsoever. The only guards are:

1. `self.general_prerequisites()` — paused check.
2. `current_block_number > self.last_reward_block.read()` — replay guard (line 1454–1458).
3. Staker existence and activity checks.

There is no `assert_caller_is_sequencer()` or equivalent. The `last_reward_block` storage variable is **global** (not per-staker): writing it at line 1485 blocks every subsequent call in the same block for every staker.

Contrast this with `update_rewards_from_attestation_contract` (line 1400), which correctly enforces `self.assert_caller_is_attestation_contract()`. The consensus-rewards path has no analogous guard.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Once consensus rewards are active (`is_pre_consensus()` returns false), an attacker calls `update_rewards(any_valid_staker, disable_rewards: true)` at the first transaction of every block. This:

1. Passes all checks (staker exists, block is new).
2. Writes `last_reward_block = current_block` (line 1485).
3. Returns early without distributing any rewards (line 1487–1488: `if disable_rewards || self.is_pre_consensus() { return; }`).

When the legitimate sequencer subsequently attempts to call `update_rewards` for the actual block producer, it reverts with `REWARDS_ALREADY_UPDATED`. No staker earns rewards for that block. Repeated every block, this permanently freezes all consensus-era yield for all stakers and their delegators.

---

### Likelihood Explanation

**Medium.**

- The call is permissionless and cheap (one transaction per block).
- The attacker needs no stake, no special role, and no profit motive.
- The attack is sustainable indefinitely as long as the attacker can front-run or race the sequencer's own `update_rewards` call.
- The only friction is the cost of one transaction per block on Starknet L2.

---

### Recommendation

Add an access-control assertion at the top of `update_rewards`, analogous to the check already present in `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.assert_caller_is_sequencer(); // <-- add this
    self.general_prerequisites();
    ...
}
```

The sequencer address should be stored in contract storage (set at initialization or by governance) and validated here. Alternatively, use Starknet's built-in `get_sequencer_address()` syscall if available in the target Cairo version.

---

### Proof of Concept

```
// Consensus rewards are active.
// Attacker address: 0xDEAD (no stake, no role)

loop every block:
    call Staking::update_rewards(
        staker_address = <any valid staker>,
        disable_rewards = true
    )
    // Sets last_reward_block = current_block, returns without distributing rewards.
    // Sequencer's subsequent call reverts: REWARDS_ALREADY_UPDATED.
    // All stakers earn zero rewards for this block.
```

**Root cause location:** [1](#0-0) 

The function accepts any caller; the only guard is the block-level replay check, which the attacker consumes first.

**Spec-vs-implementation mismatch:** [2](#0-1) 

**Global `last_reward_block` write that blocks all subsequent calls in the same block:** [3](#0-2) 

**Correct pattern already used in the attestation path (missing from the consensus path):** [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L1394-1402)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
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

**File:** docs/spec.md (L1643-1646)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```
