The implementation confirms a real vulnerability. Here is the analysis:

---

### Title
Missing Sequencer-Only Access Control on `update_rewards` Allows Any Caller to Permanently Suppress Block Rewards — (File: `src/staking/staking.cairo`)

### Summary

`update_rewards` is documented as restricted to "Only starkware sequencer" but the actual implementation enforces no such check. Any unprivileged caller can invoke it with `disable_rewards: true` to consume the global `last_reward_block` slot for the current block without distributing any rewards, permanently discarding that block's yield for all stakers.

### Finding Description

The spec at `docs/spec.md` line 1645 states:

> **access control**: Only starkware sequencer.

The actual implementation delegates all access control to `general_prerequisites()`: [1](#0-0) 

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
```

There is no sequencer check anywhere in the codebase (confirmed by exhaustive grep for `assert_caller_is_sequencer`, `SEQUENCER`, `is_sequencer`, `get_sequencer` — zero matches).

Inside `update_rewards`, the critical sequence is: [2](#0-1) 

1. `general_prerequisites()` — only checks not-paused and caller ≠ zero.
2. Asserts `current_block_number > self.last_reward_block.read()` — reverts with `REWARDS_ALREADY_UPDATED` if already called this block.
3. Validates staker exists and is active.
4. **Writes `self.last_reward_block.write(current_block_number)`** — this is the global gate.
5. If `disable_rewards || self.is_pre_consensus()` → **returns immediately with no rewards distributed**.

`last_reward_block` is a single global storage slot, not per-staker. Once any call to `update_rewards` succeeds for block N (regardless of which staker was named or whether rewards were distributed), every subsequent call for block N reverts with `REWARDS_ALREADY_UPDATED`. [3](#0-2) 

### Impact Explanation

An attacker who calls `update_rewards(any_active_staker_address, disable_rewards: true)` at the start of every block:

- Consumes the block's reward slot (sets `last_reward_block`).
- Distributes zero rewards (early return at line 1487).
- Prevents the legitimate sequencer from calling `update_rewards` for that block (it will revert with `REWARDS_ALREADY_UPDATED`).
- The block's rewards are **permanently lost** — there is no catch-up mechanism; `last_reward_block` is only ever written forward.

This matches the allowed impact: **High — Permanent freezing of unclaimed yield**.

### Likelihood Explanation

- Requires no privilege, no funds, no special setup — just a valid active staker address (publicly readable from chain state).
- One transaction per block is sufficient to suppress all rewards indefinitely.
- The attacker has no profit motive but causes direct, irreversible yield loss to all stakers and delegators.
- On Starknet, transaction fees are low, making sustained griefing economically viable.

### Recommendation

Add a sequencer-only guard at the top of `update_rewards`, consistent with the spec. On Starknet this can be enforced via `starknet::get_execution_info().tx_info.account_contract_address` compared against a stored sequencer address, or via an existing role (e.g., `SEQUENCER_ROLE`) checked before any state mutation.

### Proof of Concept

```
Block N:
  Attacker tx: update_rewards(staker_A, disable_rewards=true)
    → general_prerequisites() passes (not paused, caller ≠ 0)
    → current_block_number (N) > last_reward_block (N-1) ✓
    → staker_A is active ✓
    → last_reward_block := N   ← slot consumed
    → disable_rewards=true → return (no rewards)

  Sequencer tx: update_rewards(staker_B, disable_rewards=false)
    → current_block_number (N) > last_reward_block (N) ✗
    → REVERT: REWARDS_ALREADY_UPDATED

Block N's rewards are permanently lost.
Repeat every block → all consensus rewards suppressed indefinitely.
```

The spec/implementation divergence is the root cause: [4](#0-3) [5](#0-4)

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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** docs/spec.md (L1644-1646)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```
