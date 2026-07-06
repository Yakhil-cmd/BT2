### Title
Unprivileged Caller Can Grief Stakers by Calling `update_rewards` with `disable_rewards: true` — (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract is callable by any address and accepts a `disable_rewards: bool` parameter. An attacker can call `update_rewards(victim_staker_address, true)` to advance `last_reward_block` to the current block without distributing any rewards. Because the function enforces a strict one-call-per-block invariant, the staker's own subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`, permanently losing that block's consensus rewards.

---

### Finding Description

`update_rewards` is exposed through `IStakingRewardsManager` with no caller restriction:

```rust
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();          // only checks pause flag
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
``` [1](#0-0) 

`general_prerequisites()` only checks whether the contract is paused; there is no check that the caller is the staker, the staker's reward address, or any privileged role. The `disable_rewards: true` path updates `last_reward_block` to the current block number without computing or distributing any rewards to the staker or their pools. The flow tests confirm this behaviour explicitly:

```
// Disable rewards = true with consensus on - no rewards
system.update_rewards(:staker, disable_rewards: true);
let rewards = system.staker_claim_rewards(:staker);
assert!(rewards.is_zero());

// Attempt again same block - panic  ← last_reward_block was already advanced
``` [2](#0-1) 

Because `last_reward_block` is written unconditionally (regardless of `disable_rewards`), any subsequent call in the same block — including the legitimate staker call with `disable_rewards: false` — reverts. The staker's consensus block rewards for that block are permanently lost.

The `_update_rewards` internal function, which performs the actual reward calculation and transfer, is only reached when `disable_rewards` is `false`: [3](#0-2) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker who calls `update_rewards(victim_staker, true)` in every block permanently denies the staker all consensus block rewards. The rewards are never computed and never transferred; they are simply skipped for each block the attacker races ahead. Because the staker cannot reclaim the missed block rewards retroactively (the `last_reward_block` guard prevents re-processing the same block), the yield is permanently frozen/lost.

---

### Likelihood Explanation

**Medium.** The attack requires no special privilege — any externally-owned address can call `update_rewards`. The attacker pays only gas per block. The attack can be fully automated with a simple script that calls `update_rewards(target, true)` once per block. The attacker has no direct financial gain, but the cost to execute is low and the damage to the victim is continuous and compounding.

---

### Recommendation

Add a caller restriction to `update_rewards` so that only the staker address or their registered reward address may invoke it:

```rust
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    let caller = get_caller_address();
    let staker_info = self.internal_staker_info(:staker_address);
    assert!(
        caller == staker_address || caller == staker_info.reward_address,
        "{}",
        Error::CALLER_CANNOT_UPDATE_REWARDS,
    );
    ...
```

Alternatively, if `disable_rewards: true` is only needed for administrative transitions, restrict that flag to a privileged role (e.g., `only_app_governor`).

---

### Proof of Concept

1. Staker A is actively staking with consensus rewards enabled. They plan to call `update_rewards(staker_A, false)` each block to accumulate rewards.
2. Attacker monitors the chain. In block N, the attacker submits `update_rewards(staker_A, true)` before staker A's transaction is sequenced.
3. The call succeeds: `last_reward_block` is set to N, no rewards are distributed.
4. Staker A's call `update_rewards(staker_A, false)` in block N reverts with `REWARDS_ALREADY_UPDATED`. [4](#0-3) 

5. Staker A loses all block rewards for block N permanently.
6. The attacker repeats this every block. Staker A accrues zero consensus rewards indefinitely despite having active stake.

The root cause — no caller validation on a state-mutating, reward-skipping public entry point — is entirely within the Staking contract's own code and requires no external dependency or privileged access to exploit.

### Citations

**File:** src/staking/staking.cairo (L1411-1423)
```text
            self
                ._update_rewards(
                    :staker_address,
                    strk_total_rewards: strk_epoch_rewards,
                    btc_total_rewards: btc_epoch_rewards,
                    :strk_total_stake,
                    :btc_total_stake,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
        }
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

**File:** src/flow_test/test.cairo (L2817-2820)
```text
    // Disable rewards = true with consensus off - no rewards
    system.update_rewards(:staker, disable_rewards: true);
    let rewards = system.staker_claim_rewards(:staker);
    assert!(rewards.is_zero());
```
