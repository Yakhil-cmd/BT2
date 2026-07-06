### Title
Unrestricted `update_rewards` Caller with `disable_rewards` Flag Enables Permanent Yield Freezing — (File: `src/staking/staking.cairo`)

---

### Summary
`update_rewards` in `staking.cairo` has no caller authorization. Any address can invoke it with `disable_rewards: true`, which advances the contract-wide `last_reward_block` sentinel to the current block without distributing any rewards. Because the sentinel is shared across all stakers, a single such call per block permanently discards that block's rewards for every staker.

---

### Finding Description
`update_rewards` is a public function gated only by `general_prerequisites()`, which checks that the contract is not paused and the caller is non-zero — no role or identity check is performed. [1](#0-0) 

The function accepts a caller-controlled `disable_rewards: bool` parameter. Execution always writes `current_block_number` to `last_reward_block` **before** inspecting that flag: [2](#0-1) 

When `disable_rewards` is `true`, the function returns immediately after updating the sentinel, distributing nothing. The per-block guard then prevents any subsequent legitimate call in the same block: [3](#0-2) 

`last_reward_block` is a single contract-wide value, not per-staker: [4](#0-3) 

Compare with `update_rewards_from_attestation_contract`, which correctly restricts its caller: [5](#0-4) 

The analog to the external report is direct: `_deposit()` checked `SOFT_RESTRICTED_STAKER_ROLE` but omitted `FULL_RESTRICTED_STAKER_ROLE`; here `update_rewards` checks `current_block_number > last_reward_block` (preventing double-execution) but omits any check that the caller is an authorized entity, leaving the `disable_rewards` flag open to abuse.

---

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` once per block:
1. Advances `last_reward_block` to the current block.
2. Causes the early return, skipping all reward computation and distribution.
3. Blocks every other caller for that block (`REWARDS_ALREADY_UPDATED`).

Rewards for each blocked block are irrecoverable. Sustained over time this permanently freezes all stakers' yield accumulation.

---

### Likelihood Explanation
**High.** The function is unconditionally public. The attacker needs only:
- Any valid, active staker address (trivially observable on-chain from `NewStaker` events).
- Sufficient gas to call once per block.

No privileged role, leaked key, or external dependency is required.

---

### Recommendation
Add a caller restriction to `update_rewards` analogous to `assert_caller_is_attestation_contract` used in `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
+   self.assert_caller_is_authorized_rewards_updater(); // e.g. only the consensus/block-proposer contract
    ...
}
```

Alternatively, remove the `disable_rewards` parameter from the public interface and derive the flag from on-chain state (e.g., staker attestation status) inside the function.

---

### Proof of Concept
1. Attacker observes any active staker address `S` from on-chain `NewStaker` events.
2. In every new block, attacker calls `staking.update_rewards(S, disable_rewards: true)`.
3. `last_reward_block` is set to the current block number (line 1485).
4. The `if disable_rewards` branch (line 1487) triggers an early return — no rewards distributed.
5. Any subsequent legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED` (line 1456).
6. All stakers permanently lose rewards for every blocked block; the lost yield is unrecoverable.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1394-1401)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
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
