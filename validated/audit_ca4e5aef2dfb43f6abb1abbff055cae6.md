Based on my research, I found a valid analog. The external report's vulnerability class is **specification non-compliance: a mandatory access control constraint specified in the protocol spec is absent from the implementation**, allowing an unprivileged caller to trigger a privileged state-changing function.

The direct analog in this codebase is `update_rewards` in `src/staking/staking.cairo`, which the spec mandates is callable only by the Starknet sequencer, but the implementation enforces no such check.

---

### Title
Missing "Only Starkware Sequencer" Access Control on `update_rewards` Allows Any Caller to Permanently Freeze Unclaimed Yield - (File: src/staking/staking.cairo)

### Summary

`IStakingRewardsManager::update_rewards` is specified as callable only by the Starknet sequencer, but the implementation enforces no caller check. Any unprivileged address can call it with `disable_rewards: true`, consuming the per-block reward slot (`last_reward_block`) without distributing rewards. Because `last_reward_block` is written unconditionally before the `disable_rewards` guard, the sequencer is then permanently blocked from distributing rewards for that block. Repeated every block, this permanently freezes all unclaimed yield.

### Finding Description

`docs/spec.md` lines 1644–1645 state:

```
#### access control
Only starkware sequencer.
```

The implementation at `src/staking/staking.cairo` lines 1447–1507 contains no such check:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks pause
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker validity checks ...

    // ← last_reward_block written BEFORE disable_rewards check
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // returns with NO rewards distributed
    }
    // ... reward distribution ...
}
```

`last_reward_block` is a single global storage slot (not per-staker). Writing it at line 1485 before the `disable_rewards` guard at line 1487 means:

1. Attacker calls `update_rewards(any_valid_staker, disable_rewards: true)` in block N.
2. `last_reward_block` is set to N; function returns early — zero rewards distributed.
3. Sequencer calls `update_rewards(staker, disable_rewards: false)` in block N → reverts with `REWARDS_ALREADY_UPDATED`.
4. Block N's rewards are permanently lost for every staker.

### Impact Explanation

Every block in which the attacker front-runs the sequencer, all stakers and delegators lose their block reward permanently. There is no recovery path: `last_reward_block` cannot be reset, and missed blocks are never retroactively compensated. Sustained over many blocks, this permanently freezes all unclaimed yield across the entire protocol.

**Impact category: High — Permanent freezing of unclaimed yield.**

### Likelihood Explanation

- The function is publicly callable by any EOA or contract.
- The attacker only needs to submit a transaction before the sequencer's `update_rewards` call each block.
- On Starknet, the sequencer processes transactions in order; a malicious actor can submit a low-cost transaction at the start of each block.
- No special privilege, leaked key, or external dependency is required.
- The cost to the attacker is only gas per block; the damage to the protocol is proportional to the total staked value.

### Recommendation

Add a caller check at the top of `update_rewards` that asserts `get_caller_address()` equals the expected Starknet sequencer address (stored in contract configuration), consistent with the spec's "Only starkware sequencer" access control. Alternatively, move the `self.last_reward_block.write(current_block_number)` assignment to after the `disable_rewards` guard so that a `disable_rewards: true` call does not consume the block slot.

### Proof of Concept

1. Deploy the staking system in consensus-rewards mode with one active staker.
2. At block N, before the sequencer acts, call:
   ```
   IStakingRewardsManagerDispatcher { contract_address: staking }.update_rewards(
       staker_address: <any_valid_staker>,
       disable_rewards: true,
   );
   ```
3. Observe `last_reward_block` is now N and staker's `unclaimed_rewards_own` is unchanged.
4. Sequencer's subsequent call to `update_rewards(..., disable_rewards: false)` in block N reverts with `REWARDS_ALREADY_UPDATED`.
5. Advance to block N+1 and repeat — stakers accumulate zero rewards indefinitely.

**Root cause:** [1](#0-0)  — `last_reward_block` is written unconditionally before the `disable_rewards` early-return guard, with no caller restriction.

**Spec mandate:** [2](#0-1)  — "Only starkware sequencer."

**Interface declaration (no access control documented):** [3](#0-2)

### Citations

**File:** src/staking/staking.cairo (L1484-1488)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
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
