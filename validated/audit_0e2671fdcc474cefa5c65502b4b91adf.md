### Title
Unprivileged Caller Can Permanently Freeze All Staker Block Rewards via `update_rewards(disable_rewards=true)` - (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in `staking.cairo` has no access control. Any unprivileged caller can invoke it with `disable_rewards=true`, which writes the current block number to the global `last_reward_block` storage slot **before** the rewards-distribution branch is reached. Because `last_reward_block` is a single global value (not per-staker), one such call per block permanently blocks every staker from receiving consensus block rewards for that block.

---

### Finding Description

`update_rewards` is the consensus-rewards entry point introduced in V3. Its intended caller is the consensus layer (one call per block, per attesting staker). The function signature is:

```cairo
fn update_rewards(
    ref self: ContractState,
    staker_address: ContractAddress,
    disable_rewards: bool,
)
```

The only gate is `general_prerequisites()`, which checks that the contract is not paused and the caller is non-zero. There is no role check, no allowlist, and no assertion that the caller is the attestation contract or any other trusted address.

The critical ordering inside the function is:

```cairo
// Update last block rewards.   ← written unconditionally
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;                      ← exits without distributing rewards
}
// ... actual reward distribution follows
```

`last_reward_block` is a **global** scalar:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
```

Any subsequent call to `update_rewards` in the same block hits:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

and reverts. Therefore a single call with `disable_rewards=true` per block is sufficient to prevent all stakers from receiving rewards for that block.

The analog to the external report is exact: just as `LT.allocate_stablecoins()` lacked a post-condition check after deallocating stablecoins (allowing debt to exceed available crvUSD), `update_rewards` lacks a pre-condition check on the caller before mutating the shared `last_reward_block` state, allowing an adversary to corrupt the reward-distribution state transition for the entire protocol.

---

### Impact Explanation

An attacker who calls `update_rewards(any_active_staker, disable_rewards=true)` once per block:

1. Writes `last_reward_block = current_block`.
2. Returns without distributing any STRK block rewards.
3. Causes every subsequent legitimate call in that block to revert with `REWARDS_ALREADY_UPDATED`.

Repeated every block, this **permanently freezes all consensus block rewards** for every staker and every delegation pool in the protocol. Stakers' `unclaimed_rewards_own` fields are never incremented; pool `cumulative_rewards_trace` is never updated; delegators never accrue yield.

This matches the allowed impact: **High — Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

- The function is publicly callable (no role restriction).
- The attacker needs only to submit one transaction per block; gas cost is the only barrier.
- The attacker requires no stake, no delegation, and no privileged key.
- The attack is fully permissionless and can be automated.

Likelihood: **High**.

---

### Recommendation

Restrict `update_rewards` to a trusted caller. The simplest fix mirrors the pattern already used for `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState,
    staker_address: ContractAddress,
    disable_rewards: bool,
) {
    self.general_prerequisites();
+   // Only the consensus / sequencer infrastructure may call this.
+   self.assert_caller_is_attestation_contract(); // or a dedicated consensus role
    ...
}
```

Alternatively, move the `last_reward_block.write` to **after** the `disable_rewards` branch so that a no-op call does not consume the block's reward slot.

---

### Proof of Concept

```
Block N:
  Attacker tx:  staking.update_rewards(staker=Alice, disable_rewards=true)
    → last_reward_block := N
    → returns immediately (no rewards distributed)

  Consensus tx: staking.update_rewards(staker=Alice, disable_rewards=false)
    → assert!(N > N)  ← FAILS with REWARDS_ALREADY_UPDATED

Block N+1:
  Attacker repeats → same outcome

Result: Alice (and every other staker) accrues zero block rewards indefinitely.
```

**Relevant code references:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1507)
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

            // Get current block data and update rewards.
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
            let (strk_block_rewards, btc_block_rewards) = self
                .calculate_block_rewards(:reward_supplier_dispatcher, :curr_epoch);
            self
                ._update_rewards(
                    :staker_address,
                    strk_total_rewards: strk_block_rewards,
                    btc_total_rewards: btc_block_rewards,
                    strk_total_stake: staker_total_strk_balance,
                    btc_total_stake: staker_total_btc_balance,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
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
