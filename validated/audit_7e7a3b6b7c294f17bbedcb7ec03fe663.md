### Title
Missing Access Control on `update_rewards` Allows Anyone to Set Global `last_reward_block` Flag with `disable_rewards: true`, Permanently Freezing All Stakers' Consensus Rewards - (File: `src/staking/staking.cairo`)

---

### Summary

`IStakingRewardsManager::update_rewards` in `src/staking/staking.cairo` has no caller access control despite the specification explicitly requiring "Only starkware sequencer." The function accepts a caller-controlled `disable_rewards: bool` parameter and unconditionally writes the global `last_reward_block` storage slot **before** checking `disable_rewards`. Any unprivileged address can call `update_rewards(any_valid_staker, disable_rewards: true)` each block to set the global one-time-per-block flag without distributing rewards, permanently blocking the legitimate sequencer call (`disable_rewards: false`) for that block. Repeated across every block, this freezes all consensus-phase staker and delegator yield indefinitely.

---

### Finding Description

`update_rewards` is the sole mechanism for distributing per-block consensus rewards to stakers and their delegation pools. The specification states its access control is "Only starkware sequencer," but the implementation enforces no such restriction.

The function body is:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks pause flag
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker validity checks ...

    // Update last block rewards.          ← flag written BEFORE the early-return guard
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;                            ← exits without distributing rewards
    }
    // ... actual reward distribution ...
}
```

The global `last_reward_block` is written unconditionally at line 1485, regardless of whether `disable_rewards` is `true`. The early-return at line 1487 then exits without distributing any rewards. Because `last_reward_block` is a single global `BlockNumber` (not per-staker), any call — from any address, for any valid staker — consumes the slot for the entire block.

**Attack path:**

1. Attacker observes a new block N is produced.
2. Attacker calls `update_rewards(any_active_staker, disable_rewards: true)`.
3. `last_reward_block` is set to N; no rewards are distributed.
4. The legitimate sequencer call `update_rewards(staker, disable_rewards: false)` in block N reverts with `REWARDS_ALREADY_UPDATED`.
5. Attacker repeats every block.

The attacker only needs a valid, active staker address — public on-chain information. No privileged role, no capital, and no front-running of a specific transaction is required; the attacker simply races to be first in each block.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

`last_reward_block` is global. A single `update_rewards(..., disable_rewards: true)` call per block prevents **all** stakers and their delegators from accruing any consensus-phase block rewards for that block. Sustained across every block, this permanently freezes the entire consensus reward stream for all participants. Stakers and delegators accumulate zero `unclaimed_rewards_own` despite having active, locked stake.

---

### Likelihood Explanation

**High.** The entry point is a public, permissionless function. The only prerequisite is knowing one active staker address, which is trivially obtained from on-chain events (`NewStaker`). The cost is one cheap Starknet transaction per block. No special knowledge, capital, or coordination is required.

---

### Recommendation

Add a caller check at the top of `update_rewards` to restrict it to the authorized sequencer address (or a dedicated role), consistent with the specification:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
+   self.assert_caller_is_sequencer(); // enforce "Only starkware sequencer"
    ...
```

Alternatively, move `self.last_reward_block.write(current_block_number)` to **after** the `disable_rewards || is_pre_consensus()` guard so that a no-op call does not consume the per-block slot.

---

### Proof of Concept

```
// Pseudocode — no privileged setup required
let attacker = any_address;
let valid_staker = read_any_NewStaker_event(); // public on-chain

// Every block:
loop {
    staking.update_rewards(valid_staker, disable_rewards: true);
    // last_reward_block = current_block; no rewards distributed.

    // Sequencer's legitimate call now reverts:
    // staking.update_rewards(staker, disable_rewards: false)
    //   → assert!(current_block > last_reward_block) → PANIC: REWARDS_ALREADY_UPDATED
    advance_block();
}
// All stakers' unclaimed_rewards_own remain zero indefinitely.
```

The existing test suite already demonstrates the blocking behavior:

```cairo
// From src/flow_test/test.cairo (update_rewards_disable_rewards_consensus_rewards_flow_test)
system.update_rewards(:staker, disable_rewards: true);   // sets last_reward_block
let result = system.staking.rewards_manager_safe_dispatcher()
    .update_rewards(staker_address: staker.staker.address, disable_rewards: false);
assert_panic_with_error(:result, expected_error: StakingError::REWARDS_ALREADY_UPDATED.describe());
```

The only missing step is that the test calls both from the same (unprivileged) address, confirming no access control exists.

---

**Root cause lines:** [1](#0-0) 

**Global `last_reward_block` storage declaration:** [2](#0-1) 

**Specification stating "Only starkware sequencer":** [3](#0-2) 

**Existing test confirming the block behavior (no caller restriction):** [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1489)
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

            // Assert staker exists and active.
            // Staker is considered to exist from the moment of `stake` (when `InternalStakerInfo`
            // struct is created) until the calling to `unstake_action` (when `InternalStakerInfo`
            // struct is deleted).
            // Staker remains active until the intent period begins, i.e. K epochs after
            // `unstake_intent` is called.
            let staker_info = self.internal_staker_info(:staker_address);
            let curr_epoch = self.get_current_epoch();
            assert!(
                self.is_staker_active(:staker_address, epoch_id: curr_epoch),
                "{}",
                Error::INVALID_STAKER,
            );

            let staker_pool_info = self.staker_pool_info.entry(staker_address).as_non_mut();
            let (staker_total_strk_balance, staker_total_btc_balance) = self
                .get_staker_total_strk_btc_balance_at_epoch(
                    :staker_address, :staker_pool_info, epoch_id: curr_epoch,
                );
            // Assert staker has non-zero balance.
            // Staker exists with zero balance for the first K epochs after `stake`, then the stake
            // becomes effective.
            assert!(staker_total_strk_balance.is_non_zero(), "{}", Error::INVALID_STAKER);

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

**File:** src/flow_test/test.cairo (L2817-2829)
```text
    // Disable rewards = true with consensus off - no rewards
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
```
