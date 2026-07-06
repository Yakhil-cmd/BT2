### Title
Missing Caller Verification on `update_rewards` Allows Any User to Steal or Permanently Deny Block Rewards - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in `StakingRewardsManagerImpl` is documented as callable only by the "starkware sequencer" but contains no on-chain caller check. Because a single global `last_reward_block` gate allows only one reward distribution per block, any unprivileged staker can frontrun the sequencer to redirect that block's rewards to themselves, or call with `disable_rewards: true` to permanently destroy the block's reward allocation.

### Finding Description

The protocol spec for `update_rewards` states:

> **access control**: Only starkware sequencer.

The implementation at `src/staking/staking.cairo` lines 1449–1507 contains no such check:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();          // only checks pause state
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... no assert on get_caller_address()
    self.last_reward_block.write(current_block_number);
    if disable_rewards || self.is_pre_consensus() { return; }
    let (strk_block_rewards, btc_block_rewards) = self
        .calculate_block_rewards(...);
    self._update_rewards(:staker_address, ...);
}
```

The global `last_reward_block` storage variable (line 187) is the sole gate: once any call succeeds in a given block, all subsequent calls in that block revert with `REWARDS_ALREADY_UPDATED`. This means:

**Attack path A – reward theft:**
1. Attacker monitors the mempool/block for the sequencer's pending `update_rewards(victim_staker, false)` call.
2. Attacker submits `update_rewards(attacker_staker, false)` in the same block with higher priority.
3. `last_reward_block` is set to the current block; attacker's staker receives all block rewards accumulated since the previous `last_reward_block`.
4. The sequencer's call reverts. The victim staker receives nothing for that block.

**Attack path B – permanent yield destruction:**
1. Attacker calls `update_rewards(any_staker, disable_rewards: true)` in block N.
2. `last_reward_block` advances to N; no rewards are minted or credited.
3. The sequencer cannot call `update_rewards` again for block N.
4. The yield that should have been distributed for all blocks since the previous `last_reward_block` is permanently lost — it is never credited to any staker.

Test evidence confirms no caller restriction exists: `update_rewards` is called in tests without any `cheat_caller_address_once` wrapper (e.g., `src/staking/tests/test.cairo` line 3515, `src/flow_test/test.cairo` line 2891).

### Impact Explanation

- **Theft of unclaimed yield (High):** An attacker who is a registered staker can call `update_rewards` for their own `staker_address` before the sequencer, capturing block rewards that the protocol intended for a different staker. Repeated every block, the attacker can drain the entire consensus-phase reward stream.
- **Permanent freezing of unclaimed yield (High):** Calling with `disable_rewards: true` advances `last_reward_block` without distributing anything. The skipped block's reward allocation is never recoverable; it is permanently destroyed.

### Likelihood Explanation

- No privileged access is required; any registered staker can call `update_rewards`.
- Starknet transactions are publicly visible before inclusion; frontrunning is straightforward.
- The attack is repeatable every block at negligible cost.
- Consensus rewards are already active on mainnet, so the vulnerable code path is live.

### Recommendation

Add an explicit caller check inside `update_rewards` that restricts execution to the authorized sequencer address (stored in contract storage and settable by governance), mirroring the pattern used for `update_rewards_from_attestation_contract`:

```cairo
assert!(
    get_caller_address() == self.sequencer_address.read(),
    "{}",
    Error::CALLER_IS_NOT_SEQUENCER,
);
```

Alternatively, if the sequencer address is not known at deploy time, use a dedicated role (e.g., `SEQUENCER_ROLE`) managed through the existing `RolesComponent`.

### Proof of Concept

```
// Block N, attacker submits before sequencer:
IStakingRewardsManagerDispatcher { contract_address: staking }
    .update_rewards(staker_address: attacker_staker_address, disable_rewards: false);
// → attacker_staker receives all block rewards accumulated since last_reward_block
// → last_reward_block = N

// Sequencer's call in same block N:
IStakingRewardsManagerDispatcher { contract_address: staking }
    .update_rewards(staker_address: victim_staker_address, disable_rewards: false);
// → PANICS: REWARDS_ALREADY_UPDATED
// → victim_staker receives zero rewards for block N
```

For the griefing variant, replace `disable_rewards: false` with `disable_rewards: true` and use any valid `staker_address`; the result is the same gate advancement with zero rewards distributed.