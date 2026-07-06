### Title
`update_rewards()` Permanently Consumes Block Reward Slot When Called With `disable_rewards: true` - (File: `src/staking/staking.cairo`)

### Summary

`update_rewards()` unconditionally writes `last_reward_block` to the current block number before checking the `disable_rewards` flag. Any unprivileged caller can invoke `update_rewards(any_active_staker, disable_rewards: true)` to consume the global block-reward slot without distributing any rewards, permanently preventing all stakers from receiving rewards for that block.

### Finding Description

`update_rewards` is a public, permissionless function in `StakingRewardsManagerImpl`. Its guard at the top asserts that the current block number is strictly greater than `last_reward_block`: [1](#0-0) 

After validating the staker, the function unconditionally advances `last_reward_block` to the current block: [2](#0-1) 

Only *after* that write does it check `disable_rewards`: [3](#0-2) 

Because `last_reward_block` is a single global storage slot shared across all stakers: [4](#0-3) 

once it is written to block N, every subsequent call to `update_rewards` in block N fails with `REWARDS_ALREADY_UPDATED`, regardless of which staker is targeted. The rewards for block N are permanently unrecoverable.

The access control is only `general_prerequisites()`, which checks the contract is not paused and the caller is non-zero: [5](#0-4) 

No role or ownership check restricts who may pass `disable_rewards: true`.

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` in block N permanently destroys the block-reward distribution opportunity for *all* stakers for block N. Repeating this call once per block (a cheap, permissionless transaction) causes a sustained, complete denial of consensus-based staking rewards across the entire protocol.

### Likelihood Explanation

**High.** The entry point is fully public, requires no privileged role, and only needs a valid active staker address (trivially obtained from on-chain events or `get_stakers()`). The cost to the attacker is one transaction per block; the damage is protocol-wide reward loss.

### Recommendation

Move `self.last_reward_block.write(current_block_number)` to *after* the `disable_rewards` guard, so that the global slot is only consumed when rewards are actually distributed:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}

// Only advance the block pointer when rewards are actually distributed.
self.last_reward_block.write(current_block_number);

// ... distribute rewards ...
```

### Proof of Concept

1. Staker Alice is active with non-zero STRK balance.
2. In block N, attacker calls `update_rewards(alice_address, disable_rewards: true)`.
3. `last_reward_block` is written to N; the function returns early — no rewards distributed.
4. In the same block N, the legitimate consensus node calls `update_rewards(alice_address, disable_rewards: false)`.
5. The assertion `current_block_number > self.last_reward_block.read()` evaluates `N > N` → **false** → reverts with `REWARDS_ALREADY_UPDATED`.
6. Block N's rewards for Alice (and every other staker) are permanently lost.
7. The attacker repeats step 2 every block at negligible cost, achieving a sustained, complete freeze of all staking rewards.

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
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
