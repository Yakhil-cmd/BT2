### Title
Missing Guard on `last_reward_block` Update When `disable_rewards: true` Enables Griefing of All Staker Consensus Rewards - (File: `src/staking/staking.cairo`)

### Summary
The `update_rewards` function unconditionally writes `last_reward_block` before checking the caller-controlled `disable_rewards` flag. Because the function has no access control beyond a pause/zero-address check, any unprivileged caller can invoke it with `disable_rewards: true` every block, consuming the per-block reward slot without distributing any rewards and permanently blocking all stakers from receiving consensus rewards.

### Finding Description
`StakingRewardsManagerImpl::update_rewards` is the sole path for distributing consensus (V3) block rewards. Its guard against double-claiming is a single global storage variable `last_reward_block`:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

After all staker-validity assertions pass, the function writes `last_reward_block` **unconditionally**, before it checks `disable_rewards`:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // slot consumed here

if disable_rewards || self.is_pre_consensus() {
    return;                                            // no rewards distributed
}
```

The function's only access control is `general_prerequisites()`, which checks only that the contract is unpaused and the caller is non-zero:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
```

There is no role check, no restriction on who may pass `disable_rewards: true`, and no restriction on which `staker_address` may be supplied (any currently active staker address suffices, and those are emitted publicly in `NewStaker` events).

**Attack path:**
1. Attacker picks any active `staker_address` from on-chain events.
2. Each block, attacker calls `update_rewards(staker_address, disable_rewards: true)`.
3. `last_reward_block` is set to the current block number.
4. The function returns immediately — zero rewards distributed.
5. Any legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
6. All stakers lose their consensus block rewards for that block.

Because Starknet block times are ~3 s and L2 gas costs are low, this loop is economically viable for an attacker with no profit motive.

The analog to H-07 is direct: just as the DYAD liquidation check only tested total CR and missed the exogenous-collateral sub-condition, `update_rewards` only tests `last_reward_block` and misses the sub-condition that the slot should only be consumed when rewards are actually being distributed.

### Impact Explanation
All stakers are denied consensus rewards for every block the attacker targets. Sustained for even a single epoch this constitutes **permanent freezing of unclaimed yield** for all active stakers and their delegators, matching the High impact tier.

### Likelihood Explanation
The entry path requires no privilege, no leaked key, and no external dependency — only a valid staker address (public) and one cheap L2 transaction per block. The attack is fully automatable.

### Recommendation
Move `last_reward_block.write` inside the rewards-distribution branch so the slot is only consumed when rewards are actually sent:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}

// Only consume the reward slot when rewards are distributed.
self.last_reward_block.write(current_block_number);

let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
// ... rest of reward distribution
```

Alternatively, add a role check (e.g., `only_operator`) to restrict who may call `update_rewards` with `disable_rewards: true`.

### Proof of Concept
```
Block N:
  attacker → staking.update_rewards(active_staker, disable_rewards=true)
    → last_reward_block := N
    → returns (no rewards)

  active_staker → staking.update_rewards(active_staker, disable_rewards=false)
    → assert(N > N)  ← FAILS: REWARDS_ALREADY_UPDATED
    → staker receives 0 rewards for block N

Repeat every block → all consensus rewards permanently frozen.
```

**Root cause location:** [1](#0-0) 

**Guard that is bypassed:** [2](#0-1) 

**Absent access control:** [3](#0-2)

### Citations

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
