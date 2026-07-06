### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Block Per-Block Rewards - (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract is specified to be callable **only by the Starkware sequencer**, but the implementation contains no such access control check. Any unprivileged caller can invoke this function with `disable_rewards: true` to permanently prevent block rewards from being distributed for any given block, griefing stakers and delegators.

---

### Finding Description

The specification at `docs/spec.md` line 1645 explicitly states:

```
#### access control
Only starkware sequencer.
```

However, the implementation of `StakingRewardsManagerImpl::update_rewards` in `src/staking/staking.cairo` at lines 1447–1507 only calls `self.general_prerequisites()`, which checks:
1. The contract is not paused.
2. The caller is not the zero address.

There is **no check** that the caller is the Starkware sequencer.

The function unconditionally writes the current block number to the global `last_reward_block` storage variable (line 1485) before checking whether rewards should be distributed:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
```

Any subsequent call within the same block fails with `REWARDS_ALREADY_UPDATED` (line 1454–1458):

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

Because `last_reward_block` is a **single global value** (not per-staker), an attacker who calls `update_rewards(any_staker_address, disable_rewards: true)` at block N will:
1. Set `last_reward_block = N` with no rewards distributed.
2. Cause the sequencer's legitimate call at block N to revert with `REWARDS_ALREADY_UPDATED`.
3. Permanently forfeit all stakers' block rewards for block N — they can never be recovered.

This is a direct analog to the Vultisig M-01 pattern: the specification documents a restriction (access control) that was not implemented in the code.

---

### Impact Explanation

**Permanent freezing of unclaimed yield** (per block). Once `last_reward_block` is set to block N by the attacker, the sequencer cannot distribute rewards for block N. The yield for that block is permanently lost for all stakers and delegators. An attacker who repeats this every block can continuously deny all consensus-phase block rewards to the entire protocol.

This matches the allowed impact: **"Permanent freezing of unclaimed yield or unclaimed royalties"** and **"Griefing with no profit motive but damage to users or protocol"**.

---

### Likelihood Explanation

**High.** The function is publicly callable with no role restriction. The attacker needs only to:
- Know a valid active staker address (publicly observable on-chain via `NewStaker` events).
- Call `update_rewards(staker_address, disable_rewards: true)` before the sequencer in any block during the consensus rewards phase.

No capital, no special permissions, and no complex setup are required.

---

### Recommendation

Add an access control check at the top of `update_rewards` to enforce that only the Starkware sequencer (or a designated privileged role) can call it, consistent with the specification. For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.roles.only_sequencer(); // <-- add this
    self.general_prerequisites();
    ...
}
```

Alternatively, if a dedicated sequencer role does not yet exist, introduce one and register it during deployment, mirroring the existing `only_security_agent` / `only_token_admin` patterns already used in the contract.

---

### Proof of Concept

1. Consensus rewards are active (i.e., `current_epoch >= consensus_rewards_first_epoch`).
2. At block N, attacker calls:
   ```
   update_rewards(staker_address=<any_valid_staker>, disable_rewards=true)
   ```
3. The function passes all checks (not paused, caller non-zero, `N > last_reward_block`).
4. `last_reward_block` is written to `N`; no rewards are distributed (early return due to `disable_rewards=true`).
5. The Starkware sequencer attempts to call `update_rewards(staker_address, disable_rewards=false)` at block N.
6. The call reverts: `current_block_number (N) > last_reward_block (N)` is **false** → `REWARDS_ALREADY_UPDATED`.
7. All stakers receive zero block rewards for block N. The yield is permanently lost.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
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

**File:** src/staking/staking.cairo (L1483-1489)
```text

            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```
