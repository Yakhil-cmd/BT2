Looking at the codebase, I need to find a vulnerability reachable by an unprivileged caller that matches the allowed impact scope. Let me analyze the `update_rewards` function in the staking contract. [1](#0-0) 

The `update_rewards` function is part of `IStakingRewardsManager`, is `#[abi(embed_v0)]`, has no role check beyond `general_prerequisites()` (pause check), and accepts a caller-controlled `disable_rewards: bool` parameter. The global `last_reward_block` is updated unconditionally before the early-return guard. [2](#0-1) [3](#0-2) 

---

### Title
Unprotected `update_rewards` with Caller-Controlled `disable_rewards` Allows Anyone to Permanently Freeze All Staker Consensus Yield — (File: `src/staking/staking.cairo`)

### Summary
`IStakingRewardsManager::update_rewards` is a public, permissionless entry point that accepts a caller-controlled `disable_rewards` flag. Because the global `last_reward_block` is written before the early-return guard, any unprivileged caller can front-run the legitimate block-producer call each block with `disable_rewards: true`, permanently preventing all stakers from accumulating consensus rewards.

### Finding Description
`update_rewards` in `src/staking/staking.cairo` (lines 1448–1530) is exposed via `#[abi(embed_v0)]` with no access-control check beyond `general_prerequisites()` (which only enforces the pause flag). The function signature is:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
)
```

The execution path is:

1. `general_prerequisites()` — only checks `is_paused`.
2. Reads `current_block_number`.
3. Asserts `current_block_number > self.last_reward_block.read()` — reverts if already called this block.
4. **Writes `self.last_reward_block.write(current_block_number)`** — unconditionally, before the reward-distribution branch.
5. Checks `if disable_rewards || self.is_pre_consensus() { return; }` — skips all reward math and pool payouts.

Because step 4 commits the block number to storage before step 5 checks `disable_rewards`, any caller who submits `update_rewards(any_active_staker, disable_rewards: true)` first in a block:
- Permanently consumes the one allowed call for that block.
- Causes the legitimate block-producer call to revert with `REWARDS_ALREADY_UPDATED`.
- Causes every staker to lose their consensus block reward for that block.

`last_reward_block` is a **single global slot** — one poisoned call per block silences rewards for the entire protocol.

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

Consensus rewards are the primary yield mechanism for stakers and delegators in the post-consensus phase. An attacker who calls `update_rewards(valid_staker, true)` at the start of every block prevents the entire protocol from ever accumulating consensus rewards. Rewards that are never distributed are permanently lost (they are never minted/transferred). Delegators and stakers lose all yield indefinitely with no recovery path short of a governance upgrade.

### Likelihood Explanation
**Medium-High.** The attack requires:
- Knowledge of any active staker address (public via the `stakers` Vec and `NewStaker` events).
- Submitting one transaction per block with `disable_rewards: true`.

On Starknet, transaction fees are low. A griefing actor (e.g., a competing protocol, a disgruntled participant, or a censorship attacker) can sustain this indefinitely at minimal cost. No privileged key, leaked secret, or external dependency is required.

### Recommendation
Restrict `update_rewards` to a trusted caller — either the consensus/attestation contract or a designated block-producer role:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    // Add: assert caller is the authorized rewards updater
    self.assert_caller_is_rewards_updater(); // e.g., roles.only_rewards_updater()
    ...
}
```

Alternatively, move the `last_reward_block.write(...)` to **after** the `disable_rewards` guard so that a call with `disable_rewards: true` does not consume the block's reward slot.

### Proof of Concept

```
Block N begins.

Attacker (any EOA):
  → calls staking.update_rewards(staker=<any_active_staker>, disable_rewards=true)
  → general_prerequisites() passes (not paused)
  → current_block_number (N) > last_reward_block (N-1) ✓
  → last_reward_block.write(N)   ← slot consumed
  → disable_rewards == true → return (no rewards distributed)

Legitimate block producer (same block N):
  → calls staking.update_rewards(staker=<staker>, disable_rewards=false)
  → current_block_number (N) > last_reward_block (N) ✗  ← REVERTS: REWARDS_ALREADY_UPDATED

Result: All stakers and delegators receive zero consensus rewards for block N.
Repeat every block → permanent yield freeze.
```

### Citations

**File:** src/staking/staking.cairo (L1448-1490)
```text
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
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
