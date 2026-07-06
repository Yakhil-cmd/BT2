### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Block Per-Block Reward Distribution - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function is specified as callable only by the Starknet sequencer, but the implementation enforces no such restriction. Any unprivileged address can call it with `disable_rewards: true`, which unconditionally updates the global `last_reward_block` storage variable without distributing any rewards. Because the function guards against re-entry on the same block number, the legitimate sequencer call for that block is permanently blocked, causing stakers and delegators to lose their yield for every griefed block.

### Finding Description
In `src/staking/staking.cairo`, `update_rewards` is the V3 consensus-rewards distribution entry point.

The specification explicitly states:
> **access control**: Only starkware sequencer. [1](#0-0) 

However, the implementation only calls `general_prerequisites()`, which checks two things: the contract is not paused, and the caller is not the zero address. [2](#0-1) 

`general_prerequisites` itself: [3](#0-2) 

There is no sequencer-specific role check anywhere in `update_rewards`. The critical flaw is that `last_reward_block` is written **unconditionally** (line 1485) before the `disable_rewards` branch (line 1487): [4](#0-3) 

`last_reward_block` is a single **global** storage slot shared across all stakers: [5](#0-4) 

When `disable_rewards: true` is passed, the function returns after writing `last_reward_block` without distributing any rewards. Any subsequent call to `update_rewards` in the same block hits the guard: [6](#0-5) 

and reverts with `REWARDS_ALREADY_UPDATED`, permanently blocking reward distribution for that block.

### Impact Explanation
For every block where an attacker front-runs the sequencer with `update_rewards(any_active_staker, disable_rewards: true)`:

- `last_reward_block` is set to the current block number with no rewards distributed.
- The sequencer's legitimate `update_rewards` call for that block reverts.
- The block rewards (STRK and BTC) that would have been minted and credited to `unclaimed_rewards_own` for the staker and to delegation pools are permanently lost — they are never created or distributed.

This is permanent freezing of unclaimed yield for every griefed block. Because `update_rewards` is the sole mechanism for distributing per-block consensus rewards in V3, there is no recovery path. [7](#0-6) 

### Likelihood Explanation
- `update_rewards` is a public ABI function callable by any non-zero address with no role gate.
- Active staker addresses are publicly visible on-chain (emitted in `NewStaker` events and stored in the `stakers` vector).
- The attacker only needs to submit one transaction per block to grief the entire protocol's reward distribution for that block.
- Gas costs on Starknet are low, making sustained per-block griefing economically viable with no profit requirement.

### Recommendation
Add an access control check to `update_rewards` restricting it to the authorized sequencer or a designated operator role, consistent with the specification. For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.roles.only_sequencer(); // enforce spec: "Only starkware sequencer"
    ...
}
```

Alternatively, move the `last_reward_block.write(current_block_number)` call to after the `disable_rewards` check so that a no-op call does not consume the block's reward slot.

### Proof of Concept

```
// Setup: Staker A is active with non-zero STRK balance, consensus rewards are live.

// Block N:
// Step 1 — Attacker (any non-zero address) calls:
staking.update_rewards(staker_A_address, disable_rewards: true);
// → last_reward_block is written to N
// → function returns early, zero rewards distributed

// Step 2 — Sequencer calls (same block N):
staking.update_rewards(staker_A_address, disable_rewards: false);
// → PANICS: "Rewards already updated for this block"
// → staker_A.unclaimed_rewards_own unchanged
// → delegation pool receives zero STRK
// → block N yield permanently lost

// Step 3 — Attacker repeats every block.
// All stakers and delegators lose all consensus rewards indefinitely.
```

### Citations

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
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

**File:** src/staking/staking.cairo (L2348-2376)
```text
            // Update reward supplier.
            let staker_rewards = staker_own_rewards + commission_rewards;
            // Update total rewards.
            reward_supplier_dispatcher
                .update_unclaimed_rewards_from_staking_contract(
                    rewards: staker_rewards + total_pools_rewards,
                );
            // Claim pools rewards.
            claim_from_reward_supplier(
                :reward_supplier_dispatcher,
                amount: total_pools_rewards,
                token_dispatcher: strk_token_dispatcher(),
            );
            // Update staker rewards.
            staker_info.unclaimed_rewards_own += staker_rewards;

            // Update pools rewards.
            let pool_rewards_list = self.update_pool_rewards(:staker_address, :pools_rewards_data);
            // Emit event.
            self
                .emit(
                    Events::StakerRewardsUpdated {
                        staker_address, staker_rewards, pool_rewards: pool_rewards_list.span(),
                    },
                );

            // Write staker rewards to storage.
            self.write_staker_info(:staker_address, :staker_info);
        }
```
