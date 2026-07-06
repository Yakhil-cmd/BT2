### Title
Permissionless `update_rewards` with `disable_rewards=true` consumes global `last_reward_block` slot, permanently denying one block of yield to all stakers - (File: src/staking/staking.cairo)

---

### Summary

`IStakingRewardsManager::update_rewards` carries no on-chain caller check. It unconditionally writes `last_reward_block = current_block_number` before branching on `disable_rewards`. Any unprivileged caller can invoke it with `disable_rewards=true`, consuming the single per-block reward slot for the entire contract and permanently destroying that block's yield for every staker.

---

### Finding Description

`update_rewards` is the consensus-phase reward distribution entry point. Its implementation in `StakingRewardsManagerImpl` is:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // no caller role check
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker existence / balance checks ...

    // *** Rate-limit slot consumed unconditionally ***
    self.last_reward_block.write(current_block_number);   // line 1485

    if disable_rewards || self.is_pre_consensus() {
        return;                                           // line 1487-1488 — zero rewards distributed
    }
    // ... actual reward calculation and distribution ...
}
``` [1](#0-0) 

`last_reward_block` is a **single global** `BlockNumber` field, not a per-staker map: [2](#0-1) 

The guard at line 1454–1458 enforces **one successful call per block for the entire contract**. Because `last_reward_block` is written at line 1485 before the early-return at line 1487, a call with `disable_rewards=true` burns the slot while distributing nothing.

The spec documents the intended access control as "Only starkware sequencer": [3](#0-2) 

However, the actual implementation contains no on-chain role assertion for this function. Flow tests confirm this: `system.update_rewards(:staker, disable_rewards: false)` is called throughout without any `cheat_caller_address` setup, meaning the default (unprivileged) test address succeeds. [4](#0-3) 

Unit tests similarly call `staking_rewards_dispatcher.update_rewards(...)` directly without impersonating a privileged role: [5](#0-4) 

---

### Impact Explanation

In the consensus-rewards phase, `update_rewards` is the sole mechanism by which per-block STRK (and BTC) rewards are calculated and credited to stakers and pools. If the slot for block N is consumed with `disable_rewards=true`, the sequencer's subsequent call for block N reverts with `REWARDS_ALREADY_UPDATED`. The rewards that would have been minted for block N are **never calculated, never added to `unclaimed_rewards`, and never recoverable** — the loss is permanent.

Because `last_reward_block` is global, a single griefing call denies rewards to **all stakers** for that block. The attack is repeatable every block at negligible cost (one transaction per block).

Mapped impact: **High — Permanent freezing of unclaimed yield.** [6](#0-5) 

---

### Likelihood Explanation

- The function is callable by any address with a valid (active, non-zero-balance) staker address as argument — no token ownership or privileged key required.
- Valid staker addresses are publicly observable on-chain.
- The cost is one transaction per block; a motivated griefer (e.g., a competing validator or MEV bot) can sustain this indefinitely.
- The attack is most damaging during high-yield periods or when `yearly_mint` is large.

---

### Recommendation

1. **Add an on-chain caller check** matching the spec's stated access control. Gate `update_rewards` behind a sequencer/keeper role (e.g., `self.roles.only_sequencer()` or equivalent), consistent with the spec's "Only starkware sequencer" requirement.
2. **Alternatively**, separate the rate-limit write from the reward-distribution path: only write `last_reward_block` when rewards are actually distributed (i.e., move the write inside the `if !disable_rewards && !is_pre_consensus()` branch). This prevents zero-yield calls from consuming the slot.

---

### Proof of Concept

```
1. Consensus rewards are active (post `consensus_rewards_first_epoch`).
2. Attacker observes any valid, active staker address S on-chain.
3. At the start of block N, attacker calls:
       staking.update_rewards(staker_address=S, disable_rewards=true)
   → last_reward_block is written to N (line 1485)
   → function returns early (line 1487), zero rewards distributed
4. Sequencer attempts:
       staking.update_rewards(staker_address=S, disable_rewards=false)
   → panics: REWARDS_ALREADY_UPDATED (current_block_number == last_reward_block)
5. All stakers permanently lose block N's worth of STRK and BTC rewards.
6. Repeat each block.
``` [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L187-187)
```text
        last_reward_block: BlockNumber,
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

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/flow_test/test.cairo (L3982-3992)
```text
    system.update_rewards(:staker, disable_rewards: false);
    let mut staker_rewards = system.staker_claim_rewards(:staker);
    // Same epoch - same rewards.
    advance_blocks(blocks: 1, block_duration: AVG_BLOCK_DURATION);
    blocks_till_next_epoch -= 1;
    system.update_rewards(:staker, disable_rewards: false);
    assert!(system.staker_claim_rewards(:staker) == staker_rewards);
    advance_blocks(blocks: 100, block_duration: AVG_BLOCK_DURATION);
    blocks_till_next_epoch -= 100;
    system.update_rewards(:staker, disable_rewards: false);
    assert!(system.staker_claim_rewards(:staker) == staker_rewards);
```

**File:** src/staking/tests/test.cairo (L3956-3963)
```text
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    // Catch REWARDS_ALREADY_UPDATED.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
```
