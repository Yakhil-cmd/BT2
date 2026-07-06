### Title
Missing Caller Validation in `update_rewards` Allows Any Address to Permanently Freeze Staker Yield — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract is documented as callable "Only starkware sequencer," but the implementation contains no such enforcement. Any unprivileged address can call it, consuming the single per-block reward slot and permanently discarding that block's yield before the sequencer can act.

---

### Finding Description

`StakingRewardsManagerImpl::update_rewards` (lines 1448–1507 of `src/staking/staking.cairo`) is the consensus-rewards distribution entry point. Its only gate is `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero: [1](#0-0) 

There is no check that `get_caller_address()` equals the authorized sequencer address. The spec explicitly states: [2](#0-1) 

Immediately after the staker-validity checks, the function writes the current block number into `last_reward_block`: [3](#0-2) 

This single write is the only per-block guard. Any subsequent call in the same block — including the sequencer's legitimate call — reverts with `REWARDS_ALREADY_UPDATED`. The `disable_rewards` flag is a caller-controlled boolean that, when set to `true`, causes the function to return immediately after updating `last_reward_block` without distributing any rewards: [4](#0-3) 

---

### Impact Explanation

An attacker calls `update_rewards(staker_address: <any_valid_staker>, disable_rewards: true)` in block `X`:

1. `last_reward_block` is set to `X`.
2. No rewards are calculated or distributed.
3. The sequencer's call for block `X` reverts with `REWARDS_ALREADY_UPDATED`.
4. The block rewards for `X` are permanently lost — they are not carried forward to any future block.

Repeated across every block, this permanently freezes all consensus-era yield for every staker and their delegators. This matches the allowed impact: **High — Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

The entry point is fully public. The attacker needs only to submit a transaction before the sequencer's transaction in each target block. The cost is gas per block. No privileged access, leaked key, or external dependency is required. The attack is reachable by any unprivileged staker or public caller.

---

### Recommendation

Add an explicit sequencer-address check at the top of `update_rewards`, analogous to the pattern already used for the attestation contract: [5](#0-4) 

Store the authorized sequencer address in contract storage during construction and assert `get_caller_address() == sequencer_address` before any state mutation in `update_rewards`.

---

### Proof of Concept

```
// Block X
// Attacker (any address) submits first:
staking.update_rewards(
    staker_address: <any_active_staker>,
    disable_rewards: true
);
// → last_reward_block = X, no rewards distributed

// Sequencer submits second (same block X):
staking.update_rewards(
    staker_address: <intended_staker>,
    disable_rewards: false
);
// → PANICS: REWARDS_ALREADY_UPDATED
// Block X rewards are permanently lost.
```

The root cause is at: [6](#0-5) 

The missing guard is the absence of any `assert!(get_caller_address() == self.sequencer_address.read(), ...)` before line 1453, in direct contradiction with the specification: [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L1399-1401)
```text
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

**File:** src/staking/staking.cairo (L1448-1458)
```text
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

**File:** docs/spec.md (L1643-1646)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```
