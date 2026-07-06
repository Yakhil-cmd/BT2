### Title
Unrestricted `update_rewards` Allows Any Caller to Permanently Freeze All Staker Yield — (`src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the staking contract has no access control. Any unprivileged caller can invoke it with `disable_rewards = true` for any valid staker address. This updates the **global** `last_reward_block` without distributing rewards, permanently blocking legitimate reward distribution for that block across all stakers.

---

### Finding Description

`update_rewards` is implemented in `StakingRewardsManagerImpl` and is a fully public function. Its only gate is `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero — no role or identity check is performed. [1](#0-0) 

The function accepts a `disable_rewards: bool` parameter. When `true`, the function writes the current block number to the **global** `last_reward_block` storage slot and then returns early, distributing nothing:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;   // ← early return, no rewards distributed
}
``` [2](#0-1) 

Because `last_reward_block` is a **single global value** (not per-staker), any call to `update_rewards` — regardless of which `staker_address` is passed — consumes the slot for the entire block. A subsequent legitimate call in the same block fails with `REWARDS_ALREADY_UPDATED`:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [3](#0-2) 

The attacker only needs to supply any currently-active staker address (the function validates this at line 1466–1482) and set `disable_rewards = true`. The rewards for that block are not redistributed — they are simply never minted/claimed. [4](#0-3) 

---

### Impact Explanation

An attacker calling `update_rewards(any_active_staker, disable_rewards: true)` once per block (~3 s on Starknet) permanently prevents **all** stakers from receiving consensus-phase block rewards. The lost rewards are never recovered. This constitutes **permanent freezing of unclaimed yield** (High) and, if sustained, **protocol insolvency** in the rewards pipeline (Critical).

---

### Likelihood Explanation

- The function is fully public with no role restriction.
- The attacker needs only a valid staker address (publicly observable on-chain).
- The cost is gas per block — no capital at risk.
- The attack is trivially automatable.

---

### Recommendation

Restrict `update_rewards` to an authorized caller (e.g., the attestation contract or a dedicated consensus rewards distributor), mirroring the access control already applied to `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards_from_attestation_contract(...) {
    ...
    self.assert_caller_is_attestation_contract(); // ← existing pattern
    ...
}
``` [5](#0-4) 

Add an equivalent `assert_caller_is_authorized_rewards_manager()` guard at the top of `update_rewards`.

---

### Proof of Concept

1. Observe any active staker address `S` on-chain.
2. At block `N`, call `staking.update_rewards(S, disable_rewards: true)`.
3. `last_reward_block` is written to `N`; no rewards are distributed.
4. Any legitimate call to `update_rewards` at block `N` reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeat every block → all stakers permanently receive zero consensus rewards.

The vulnerability class is a direct analog to the external report: **missing validation/access control → early return skips critical logic (reward distribution instead of swap execution) → permanent loss of yield for all participants**.

### Citations

**File:** src/staking/staking.cairo (L1394-1402)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
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
