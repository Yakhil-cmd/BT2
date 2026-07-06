### Title
Unprivileged Caller Can Permanently Freeze All Block Rewards via `update_rewards(disable_rewards: true)` — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract is publicly callable with no role-based access control. An unprivileged caller can invoke it with `disable_rewards: true`, which advances the global `last_reward_block` checkpoint but skips reward distribution entirely. Because `last_reward_block` is written **before** the `disable_rewards` guard, the block's rewards are permanently destroyed and no legitimate caller can recover them for that block.

---

### Finding Description

`update_rewards` is exposed via `#[abi(embed_v0)]` with no caller restriction beyond `general_prerequisites()`, which only checks that the contract is unpaused and the caller is non-zero address. [1](#0-0) 

The function accepts a `disable_rewards: bool` parameter. When `true`, the execution path is:

1. `last_reward_block` is written to `current_block_number` unconditionally.
2. The function returns immediately without calling `_update_rewards`. [2](#0-1) 

`last_reward_block` is a **single global storage variable**, not per-staker. [3](#0-2) 

The one-call-per-block guard asserts `current_block_number > last_reward_block`, so once the attacker's call succeeds, no other caller can distribute rewards for that block. [4](#0-3) 

This is the direct analog to the external report's root cause: just as the Foundation contract used a single `isCreator` flag derived from an attacker-controlled input to route **all** revenue away from the legitimate recipient, here a single attacker-controlled boolean (`disable_rewards`) causes the global reward checkpoint to advance while routing **zero** rewards to any staker — permanently, for that block.

---

### Impact Explanation

An attacker calling `update_rewards(any_valid_staker, disable_rewards: true)` once per block permanently destroys all stakers' block rewards for that block. Sustained across every block, this freezes all unclaimed yield across the entire protocol with no recovery path.

**Impact: High — Permanent freezing of unclaimed yield.**

---

### Likelihood Explanation

The attack requires only:
- A valid staker address (publicly available from `NewStaker` events emitted on-chain).
- One transaction per block (minimal gas cost, no capital at risk).

No privileged access, leaked keys, bridge compromise, or external dependency is required. Any unprivileged EOA can execute this.

---

### Recommendation

1. **Access control**: Restrict `update_rewards` to a trusted caller (e.g., the attestation contract or a dedicated rewards-manager role), consistent with how `update_rewards_from_attestation_contract` is already gated by `assert_caller_is_attestation_contract()`. [5](#0-4) 

2. **Order fix**: Move `self.last_reward_block.write(current_block_number)` to **after** the `disable_rewards` guard, so a skipped distribution does not consume the block's reward slot.

---

### Proof of Concept

1. Attacker reads any valid `staker_address` `S` from a past `NewStaker` event.
2. At the start of each block, attacker calls `update_rewards(S, disable_rewards: true)`.
3. `last_reward_block` is updated to the current block number (line 1485).
4. Execution returns at line 1488 — `_update_rewards` is never called.
5. Any subsequent legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED` (line 1455–1458).
6. All stakers permanently lose their block rewards for that block.
7. Repeated every block, all consensus-phase protocol rewards are permanently frozen.

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1399-1401)
```text
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

**File:** src/staking/staking.cairo (L1448-1452)
```text
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
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
