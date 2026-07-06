The spec at line 1645 states `update_rewards` has access control "Only starkware sequencer." The actual implementation must be checked against this claim.

Looking at the implementation:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();  // <-- only pause check
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}", Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    self.last_reward_block.write(current_block_number);  // global gate
    if disable_rewards || self.is_pre_consensus() {
        return;  // no rewards distributed
    }
    ...
}
```

`general_prerequisites()` is shared with `stake`, `claim_rewards`, `unstake_intent`, and other user-callable functions — it only checks the pause flag. There is **no sequencer/caller check** in `update_rewards`.

`last_reward_block` is a **global** storage variable (not per-staker). The check at line 1455 enforces that only one `update_rewards` call succeeds per block, for the entire contract.

---

### Title
Missing Caller Guard on `update_rewards` Allows Any Address to Permanently Suppress Per-Block Consensus Rewards — (`src/staking/staking.cairo`)

### Summary
`update_rewards` is documented as callable only by the Starkware sequencer, but the implementation enforces no such restriction. Any unprivileged address can call it with `disable_rewards: true`, consuming the global `last_reward_block` slot for the current block and causing all stakers to lose that block's consensus rewards permanently.

### Finding Description
The spec requires "Only starkware sequencer" access control for `update_rewards`. [1](#0-0) 

The implementation only calls `general_prerequisites()`, which is a shared pause-check used by all user-facing functions and contains no caller identity check. [2](#0-1) 

`last_reward_block` is a single global storage slot. Once written for a block, no further `update_rewards` call can succeed for that block (the `REWARDS_ALREADY_UPDATED` guard fires). [3](#0-2) 

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` first in a block:
1. Passes all validation (staker exists, is active, has non-zero balance).
2. Writes `current_block_number` into `last_reward_block`.
3. Returns immediately without distributing any rewards (the `disable_rewards` branch).
4. Blocks the legitimate sequencer call for the same block with `REWARDS_ALREADY_UPDATED`.

The staker named in the call loses that block's rewards. Because the gate is global, **no other staker can receive rewards for that block either** — the sequencer cannot retry with a different staker address.

### Impact Explanation
By repeating this every block, an attacker can permanently freeze all consensus reward accrual for every active staker. Unclaimed yield that would have been minted and attributed is never created. This matches the allowed High impact: **Permanent freezing of unclaimed yield**.

### Likelihood Explanation
The call is permissionless, costs only gas, and requires no capital. The attacker only needs to submit a transaction before the sequencer's own `update_rewards` transaction in each block. On Starknet, transaction ordering within a block is controlled by the sequencer, which complicates front-running — however, the sequencer is not obligated to call `update_rewards` in every block, and any external party (including a malicious staker) can race to call it first. The absence of any caller check makes this trivially exploitable.

### Recommendation
Add a caller check at the top of `update_rewards` that asserts `get_caller_address()` equals the designated Starkware sequencer address (stored in contract storage), consistent with the spec's stated access control. Alternatively, restrict the function to a role-gated address (e.g., `SEQUENCER_ROLE`).

### Proof of Concept
1. Deploy the staking contract and register two active stakers (past the K-epoch activation window).
2. Enable consensus rewards.
3. From an arbitrary EOA (not the sequencer), call:
   ```
   update_rewards(staker_address: staker_1, disable_rewards: true)
   ```
4. Observe: call succeeds, `last_reward_block` is set to the current block, no rewards are distributed.
5. From the legitimate sequencer, attempt:
   ```
   update_rewards(staker_address: staker_1, disable_rewards: false)
   ```
6. Observe: reverts with `REWARDS_ALREADY_UPDATED`.
7. Repeat step 3 every block. After N blocks, `staker_1.unclaimed_rewards_own` remains zero despite N blocks of eligible consensus participation.

The flow test at lines 2882–2895 already demonstrates that `disable_rewards: true` produces zero rewards and that a same-block retry panics — confirming the mechanism works exactly as described above from any caller. [4](#0-3)

### Citations

**File:** docs/spec.md (L1644-1646)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
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

**File:** src/flow_test/test.cairo (L2882-2895)
```text
    // Disable rewards = true with consensus on - no rewards
    system.update_rewards(:staker, disable_rewards: true);
    let rewards = system.staker_claim_rewards(:staker);
    assert!(rewards.is_zero());

    // Attempt again same block - panic
    let result = system
        .staking
        .rewards_manager_safe_dispatcher()
        .update_rewards(staker_address: staker.staker.address, disable_rewards: true);
    assert_panic_with_error(
        :result, expected_error: StakingError::REWARDS_ALREADY_UPDATED.describe(),
    );
    advance_blocks(blocks: 1, block_duration: AVG_BLOCK_DURATION);
```
