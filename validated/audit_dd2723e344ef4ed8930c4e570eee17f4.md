### Title
Attacker Can Grief Consensus Reward Distribution by Calling `update_rewards` with `disable_rewards: true` — (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract is publicly callable by any address and accepts a caller-controlled `disable_rewards` flag. An attacker can call this function with `disable_rewards: true` for any valid staker to advance the global `last_reward_block` checkpoint without distributing any rewards, permanently blocking all stakers from receiving consensus rewards in that block.

---

### Finding Description

`IStakingRewardsManager::update_rewards` is exposed as a public, permissionless entry point:

```cairo
#[starknet::interface]
pub trait IStakingRewardsManager<TContractState> {
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
``` [1](#0-0) 

Inside the implementation, the function unconditionally writes `current_block_number` into the global `last_reward_block` storage slot **before** checking the `disable_rewards` flag:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [2](#0-1) 

The guard at the top of the function enforces a strict one-call-per-block invariant using this same global variable:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [3](#0-2) 

Because `last_reward_block` is a single global slot shared across all stakers, any call to `update_rewards` — regardless of which staker is named or whether `disable_rewards` is `true` — consumes the per-block slot for the entire protocol. [4](#0-3) 

The only access control applied is `general_prerequisites`, which merely checks the contract is not paused and the caller is non-zero:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [5](#0-4) 

Once consensus rewards are active (`is_pre_consensus()` returns `false`), `update_rewards_from_attestation_contract` is disabled by its own guard:

```cairo
assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
``` [6](#0-5) 

This means `update_rewards` is the **sole** mechanism for distributing consensus-phase rewards. Blocking it blocks all reward accrual.

---

### Impact Explanation

An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` once per block:

1. Advances `last_reward_block` to the current block without distributing any rewards.
2. Causes every subsequent legitimate `update_rewards` call in that block to revert with `REWARDS_ALREADY_UPDATED`.
3. Denies all stakers their consensus block rewards for that block.

Repeated every block, this permanently freezes all unclaimed consensus yield across the entire protocol. This matches the **High** impact tier: *Permanent freezing of unclaimed yield*.

---

### Likelihood Explanation

**Medium.** The attack requires no special privilege — only a non-zero caller address and a valid (active, non-zero-balance) staker address to pass the staker validation checks. The attacker needs to submit one transaction per block. On Starknet, transaction fees are low, making sustained griefing economically feasible. The attacker gains nothing financially, but the damage to stakers and the protocol is severe.

---

### Recommendation

The root cause is that `last_reward_block` is updated even when no rewards are distributed. The fix is to only advance the checkpoint when rewards are actually written:

```cairo
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
    // ... staker validation ...

    if disable_rewards || self.is_pre_consensus() {
        return; // Do NOT write last_reward_block here
    }

    // Only advance the checkpoint when rewards are actually distributed.
    self.last_reward_block.write(current_block_number);
    // ... reward calculation and distribution ...
}
```

Alternatively, restrict `update_rewards` to a trusted caller (e.g., the attestation contract or a designated keeper role) so that the `disable_rewards` flag cannot be weaponised by an arbitrary address.

---

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` == `false`).
2. Attacker identifies any valid, active staker `S` with non-zero balance.
3. In block `N`, attacker calls `update_rewards(S, disable_rewards: true)`.
   - Passes all checks (unpaused, non-zero caller, staker active, non-zero balance).
   - `last_reward_block` is written to `N`.
   - Function returns early — no rewards distributed.
4. Legitimate staker `T` (or a keeper) calls `update_rewards(T, disable_rewards: false)` in the same block `N`.
   - Reverts: `current_block_number (N) > last_reward_block (N)` is `false` → `REWARDS_ALREADY_UPDATED`.
5. All stakers miss their consensus rewards for block `N`.
6. Attacker repeats step 3 every block → all stakers permanently receive zero consensus rewards.

### Citations

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

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1399-1399)
```text
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
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
