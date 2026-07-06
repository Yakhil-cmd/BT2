The question's complex framing about "stale active-token state" and "epoch boundary drift" is a red herring. The real issue is simpler and more direct. Let me trace it precisely.

**Access control check in `update_rewards`:** [1](#0-0) 

The only guard is `general_prerequisites()`: [2](#0-1) 

This checks only: contract is unpaused, and caller is not the zero address. There is **no sequencer-only check**, despite the spec explicitly stating: [3](#0-2) 

**`last_reward_block` is a global (not per-staker) storage variable:** [4](#0-3) 

**The critical sequence in `update_rewards`:** [5](#0-4) 

`last_reward_block` is written to the current block **before** the `disable_rewards` early-return. This means calling with `disable_rewards: true` consumes the block slot without distributing any rewards.

**The concrete attack:**

Any non-zero address can call `update_rewards(valid_staker_address, disable_rewards: true)` in block N. This:
1. Passes all guards (unpaused, non-zero caller, staker exists and active, `current_block > last_reward_block`)
2. Writes `last_reward_block = N`
3. Returns early — no rewards distributed

When the sequencer then attempts `update_rewards(..., disable_rewards: false)` in the same block N, it hits: [6](#0-5) 

and reverts with `REWARDS_ALREADY_UPDATED`. The block's rewards are permanently lost for all stakers. The attacker can repeat this every block.

**Regarding the specific "mixed STRK/BTC epoch boundary drift" claim:**

The question's hypothesis about "stale active-token state" causing accounting divergence between STRK and BTC pools across epoch boundaries is not a distinct vulnerability. The `get_staker_total_strk_btc_balance_at_epoch` call at line 1475-1478 reads from epoch-keyed traces correctly. The `btc_tokens` active-status check is also epoch-consistent. No stale-read divergence exists beyond what the missing access control already causes.

**Conclusion:**

The missing caller restriction is a real, reachable vulnerability. An unprivileged attacker can permanently deny all per-block reward distributions by front-running every `update_rewards` call with `disable_rewards: true`. This matches **High: Permanent freezing of unclaimed yield**.

---

### Title
Missing Caller Restriction on `update_rewards` Allows Unprivileged Permanent Denial of Staker Rewards — (`src/staking/staking.cairo`)

### Summary
`update_rewards` is documented as "Only starkware sequencer" but has no such enforcement. Any non-zero address can call it with `disable_rewards: true`, consuming the global `last_reward_block` slot for the current block without distributing rewards, permanently blocking the sequencer from distributing rewards for that block.

### Finding Description
`StakingRewardsManagerImpl::update_rewards` calls only `general_prerequisites()` (unpaused + non-zero caller). The global `last_reward_block` is written unconditionally before the `disable_rewards` early-return branch. An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` in block N sets `last_reward_block = N` and causes all subsequent calls in block N to revert with `REWARDS_ALREADY_UPDATED`, regardless of the `disable_rewards` flag.

### Impact Explanation
Every block where the attacker front-runs the sequencer, all stakers lose their per-block reward share permanently. Repeated every block, this freezes all unclaimed yield accrual indefinitely. The reward supplier's `unclaimed_rewards` is never incremented for those blocks, so the debt never builds — the yield is simply destroyed.

### Likelihood Explanation
The attack requires only a non-zero address and knowledge of the current block number. It is trivially repeatable at negligible cost (one transaction per block). No privileged access, no leaked keys, no external dependencies.

### Recommendation
Add a sequencer-only caller check at the top of `update_rewards`, consistent with the spec. Either gate on a stored sequencer address or use the existing roles component.

### Proof of Concept
1. Deploy with a valid staker active for `curr_epoch`.
2. In block N, call `update_rewards(staker_address, disable_rewards: true)` from any non-zero EOA.
3. Observe `last_reward_block == N`, staker `unclaimed_rewards_own` unchanged.
4. Call `update_rewards(staker_address, disable_rewards: false)` from the sequencer in block N.
5. Observe revert: `REWARDS_ALREADY_UPDATED`.
6. Advance to block N+1; staker has permanently lost block N's reward share.

### Citations

**File:** src/staking/staking.cairo (L186-187)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
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

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
