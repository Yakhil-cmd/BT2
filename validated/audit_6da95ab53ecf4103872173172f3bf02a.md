### Title
`last_reward_block` Updated Before `disable_rewards` Guard Enables Griefing of Reward Distribution - (File: src/staking/staking.cairo)

### Summary
In `update_rewards`, the global `last_reward_block` is written unconditionally **before** the `disable_rewards || is_pre_consensus()` early-return guard. Because the function carries no on-chain caller restriction, any unprivileged address can call `update_rewards(valid_staker, disable_rewards: true)` to consume the block's single reward slot without distributing any rewards, permanently blocking the sequencer from issuing rewards for that block.

### Finding Description
`update_rewards` in `src/staking/staking.cairo` (lines 1449–1507) follows this order:

```cairo
// 1. Validate staker is active …
// 2. ← Update last block rewards UNCONDITIONALLY
self.last_reward_block.write(current_block_number);   // line 1485

// 3. Early-return if rewards are disabled or pre-consensus
if disable_rewards || self.is_pre_consensus() {
    return;                                            // line 1488
}

// 4. Calculate and distribute rewards …
``` [1](#0-0) 

The `last_reward_block` write happens at line 1485, before the guard at line 1487. The guard is the only mechanism that prevents reward distribution; once `last_reward_block` is set to the current block, the re-entry check at lines 1454–1458 will reject any subsequent call in the same block with `REWARDS_ALREADY_UPDATED`:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [2](#0-1) 

The spec states `update_rewards` is "Only starkware sequencer," but the implementation contains **no on-chain caller check** — the function's error list (`CONTRACT_IS_PAUSED`, `REWARDS_ALREADY_UPDATED`, `STAKER_NOT_EXISTS`, `INVALID_STAKER`) includes no `CALLER_IS_NOT_SEQUENCER` variant, and the code enforces none. [3](#0-2) 

Because `update_rewards` is exposed through the public `IStakingRewardsManager` interface with no caller guard, any address can invoke it. [4](#0-3) 

### Impact Explanation
An attacker calls `update_rewards(any_valid_staker, disable_rewards: true)` at the start of every block:

1. `last_reward_block` is set to the current block number.
2. The function returns early — zero rewards are distributed.
3. The legitimate sequencer's subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
4. All stakers lose their block reward for that block.

Repeated every block, this permanently freezes unclaimed yield for all stakers and their delegators. This matches **"Permanent freezing of unclaimed yield"** (High) or at minimum **"Griefing with no profit motive but damage to users or protocol"** (Medium).

### Likelihood Explanation
`update_rewards` is a public, permissionless entry point. Any EOA or contract can call it with a valid staker address and `disable_rewards: true`. The only cost is gas. The attacker does not need any stake, delegation, or privileged role. Starknet's sequencer controls transaction ordering and could attempt to front-run the attacker, but this is an operational mitigation, not a protocol-level guarantee, and cannot be relied upon as a security control.

Likelihood: **Medium** — straightforward to execute, low cost, no special access required.

### Recommendation
Move the `last_reward_block` write to **after** the `disable_rewards` guard, so the block slot is only consumed when rewards are actually distributed:

```diff
-        // Update last block rewards.
-        self.last_reward_block.write(current_block_number);
-
         if disable_rewards || self.is_pre_consensus() {
             return;
         }

+        // Update last block rewards.
+        self.last_reward_block.write(current_block_number);
+
         // Get current block data and update rewards.
```

Additionally, add an explicit on-chain caller check to enforce the "Only starkware sequencer" access control documented in the spec.

### Proof of Concept
1. Staker `S` is active and past the K-epoch delay; consensus rewards are live.
2. In block `N`, attacker calls `update_rewards(S, disable_rewards: true)`.
   - `last_reward_block` is written to `N`.
   - Function returns early; `S.unclaimed_rewards_own` is unchanged.
3. Sequencer calls `update_rewards(S, disable_rewards: false)` in the same block `N`.
   - `current_block_number (N) > last_reward_block (N)` is **false** → reverts with `REWARDS_ALREADY_UPDATED`.
4. Staker `S` (and all delegators in `S`'s pool) receive zero rewards for block `N`.
5. Attacker repeats step 2 every block → all stakers permanently receive zero rewards.

The existing test `update_rewards_disable_rewards_consensus_rewards_flow_test` already demonstrates that calling with `disable_rewards: true` produces zero rewards and sets `last_reward_block`, confirming the mechanism. [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L1447-1451)
```text
    #[abi(embed_v0)]
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
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

**File:** docs/spec.md (L1637-1652)
```markdown
#### errors <!-- omit from toc -->
1. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
2. [REWARDS\_ALREADY\_UPDATED](#rewards_already_updated)
3. [STAKER\_NOT\_EXISTS](#staker_not_exists)
4. [INVALID\_STAKER](#invalid_staker)
#### pre-condition <!-- omit from toc -->
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
1. Calculate total block rewards.
2. Calculate staker rewards (include commission) and pool rewards.
3. Update `unclaimed_rewards_own` of the staker.
4. Update and transfer rewards to the pools, if exist.
5. Update Reward Supplier's `unclaimed_rewards`.
6. Update `last_reward_block` to the current block.
```

**File:** src/flow_test/test.cairo (L2882-2895)
```text
    // Disable rewards = true with consensus on - no rewards
    system.update_rewards(:staker, disable_rewards: true);
    let rewards = system.staker_claim_rewards(:staker);
    assert!(rewards.is_zero());

    // Attempt again same block - panic
    let result = system
        .staking
        .rewards_manager_safe_dispatcher()
        .update_rewards(staker_address: staker.staker.address, disable_rewards: true);
    assert_panic_with_error(
        :result, expected_error: StakingError::REWARDS_ALREADY_UPDATED.describe(),
    );
    advance_blocks(blocks: 1, block_duration: AVG_BLOCK_DURATION);
```
