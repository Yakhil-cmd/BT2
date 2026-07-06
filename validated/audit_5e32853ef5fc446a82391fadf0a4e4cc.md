### Title
Any Caller Can Front-Run `update_rewards` With `disable_rewards: true` to Permanently Freeze Staker Reward Distribution — (`File: src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract is missing the access control mandated by the protocol specification. The spec states "Only starkware sequencer" may call it, but the implementation imposes no such restriction. Any unprivileged caller can invoke `update_rewards(staker_address, disable_rewards: true)` to consume the per-block reward slot, preventing the sequencer from distributing rewards for that block. Repeated front-running permanently freezes unclaimed yield for all stakers.

---

### Finding Description

`update_rewards` is the consensus-era reward distribution entry point. Its only guard is `general_prerequisites()`: [1](#0-0) 

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
```

There is no check that the caller is the sequencer. The function then immediately writes `last_reward_block` to the current block number **before** branching on `disable_rewards`: [2](#0-1) 

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
```

Because `last_reward_block` is a **global** (not per-staker) slot, a single call with `disable_rewards: true` consumes the reward opportunity for the entire block. Any subsequent call in the same block — including the legitimate sequencer call — reverts with `REWARDS_ALREADY_UPDATED`: [3](#0-2) 

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

The protocol specification explicitly restricts this function to the sequencer: [4](#0-3) 

> **access control**: Only starkware sequencer.

The code does not implement this restriction.

---

### Impact Explanation

An attacker who front-runs every sequencer `update_rewards` call with `disable_rewards: true` permanently prevents all block-reward distribution. No staker or delegator accrues consensus-era rewards. This constitutes **permanent freezing of unclaimed yield** for every participant in the protocol.

Even a partial attack (front-running a fraction of blocks) causes proportional, irreversible loss of yield because missed blocks are never retroactively compensated.

---

### Likelihood Explanation

**High.** The function is public, requires no tokens, no stake, and no privileged role — only a non-zero caller address. On Starknet, a transaction submitted in the same block as the sequencer's call will land first if it carries a higher fee. The attacker needs no special knowledge beyond monitoring the mempool or simply calling the function at the start of every block.

---

### Recommendation

Add an access-control check that restricts `update_rewards` to the authorized sequencer address, analogous to how `update_rewards_from_attestation_contract` is restricted: [5](#0-4) 

```cairo
assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
self.assert_caller_is_attestation_contract();
```

Store the sequencer address in contract storage and assert `get_caller_address() == sequencer_address` at the top of `update_rewards`, before any state is written.

---

### Proof of Concept

1. Consensus rewards are active (`!is_pre_consensus()`).
2. Staker `S` has been staking for `K` epochs and has non-zero balance.
3. In block `N`, the sequencer prepares to call `update_rewards(S, disable_rewards: false)`.
4. Attacker submits `update_rewards(S, disable_rewards: true)` with a higher fee in the same block.
5. Attacker's transaction executes first:
   - `last_reward_block` is set to `N`.
   - Function returns early; no rewards are distributed.
6. Sequencer's transaction executes next and reverts: `REWARDS_ALREADY_UPDATED`.
7. Staker `S` (and all pool delegators) receive zero rewards for block `N`.
8. Attacker repeats steps 3–7 every block. All staker and delegator unclaimed yield is permanently frozen at zero.

The attacker spends only gas; there is no minimum stake or token requirement.

### Citations

**File:** src/staking/staking.cairo (L1398-1401)
```text
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

**File:** src/staking/staking.cairo (L1453-1458)
```text
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
