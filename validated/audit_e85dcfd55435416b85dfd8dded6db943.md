Based on my investigation of the production code, this is a **real vulnerability**.

---

### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Suppress Block Rewards — (`src/staking/staking.cairo`)

### Summary

The spec explicitly states `update_rewards` is restricted to "Only starkware sequencer," but the implementation enforces no such check. Any unprivileged caller can invoke `update_rewards(valid_staker, disable_rewards=true)` to consume the global `last_reward_block` slot for the current block while suppressing reward distribution, permanently discarding that block's yield for all stakers.

### Finding Description

The spec at `docs/spec.md` line 1645 declares:

> **access control**: Only starkware sequencer.

The implementation at `src/staking/staking.cairo` lines 1449–1507 enforces no such restriction:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();   // only checks is_paused
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}", Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker validity checks ...
    self.last_reward_block.write(current_block_number);  // global write

    if disable_rewards || self.is_pre_consensus() {
        return;   // exits without distributing rewards
    }
    // ... reward distribution ...
}
``` [1](#0-0) 

`last_reward_block` is a **single global storage variable** — not per-staker. Once written, no further call to `update_rewards` for any staker can succeed in the same block (all revert with `REWARDS_ALREADY_UPDATED`). [2](#0-1) [3](#0-2) 

`general_prerequisites()` only checks the pause flag — it contains no sequencer/caller identity check. [4](#0-3) 

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Attack sequence per block:
1. Attacker calls `update_rewards(any_valid_active_staker, disable_rewards=true)` as the first transaction in a block.
2. `last_reward_block` is written to the current block number.
3. The function returns early at line 1487 — no rewards are distributed.
4. The legitimate sequencer's subsequent call for the intended staker reverts with `REWARDS_ALREADY_UPDATED`.
5. That block's rewards are permanently lost — there is no retry mechanism.

Repeating this every block completely starves all stakers of consensus rewards. The attacker needs only a valid (active, post-K-epoch) staker address, which is publicly observable on-chain. [5](#0-4) 

### Likelihood Explanation

**High.** The function is fully public (`#[abi(embed_v0)]`), requires no tokens, no privileged role, and no special setup beyond knowing one active staker address. The cost to the attacker is only gas per block. The attack is trivially repeatable and fully griefs the protocol's reward distribution.

### Recommendation

Add a sequencer-only caller check at the top of `update_rewards`, consistent with the spec. For example, gate the function on a stored `sequencer_address` role or use the existing roles framework already present in the contract.

### Proof of Concept

1. Deploy with two active stakers (past K-epoch activation).
2. Each new block: attacker calls `update_rewards(staker_A, disable_rewards=true)` before the sequencer.
3. Sequencer's call for `staker_B` (or `staker_A`) reverts with `REWARDS_ALREADY_UPDATED`.
4. After N blocks, both stakers have zero accumulated rewards despite being eligible — confirmed by `claim_rewards` returning zero.

This matches the existing test pattern at `src/staking/tests/test.cairo` lines 3887–3894, which already demonstrates that calling with `disable_rewards=true` followed by any second call in the same block always reverts. [6](#0-5)

### Citations

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

**File:** docs/spec.md (L1642-1645)
```markdown
#### pre-condition <!-- omit from toc -->
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/tests/test.cairo (L3886-3894)
```text
    advance_epoch_global();
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: true);
    // Catch REWARDS_ALREADY_UPDATE - with distribute = false.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
```
