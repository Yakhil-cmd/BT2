The spec at `docs/spec.md` line 1645 states `update_rewards` access control is **"Only starkware sequencer"**, but the implementation contains no such check. Let me confirm the full picture.

**Key facts from the code:**

1. `update_rewards` in `StakingRewardsManagerImpl` calls only `self.general_prerequisites()`, which checks only the pause flag — no caller/role check exists. [1](#0-0) 

2. `last_reward_block` is a **single global** storage slot (not per-staker). Once written for a block, no second call can succeed. [2](#0-1) 

3. When `disable_rewards = true`, the function writes `last_reward_block` and returns immediately — no rewards are distributed, and the block's reward slot is permanently consumed. [3](#0-2) 

4. The spec explicitly documents the intended restriction: [4](#0-3) 

---

### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Suppress Per-Block Rewards — (`src/staking/staking.cairo`)

### Summary
`update_rewards` is documented as callable only by the Starkware sequencer, but the implementation enforces no such restriction. Any unprivileged address can call it with `disable_rewards: true`, consuming the global `last_reward_block` slot for the current block without distributing any rewards. Because only one call per block is permitted, the legitimate sequencer call is permanently blocked for that block and its rewards are irrecoverably lost.

### Finding Description
`StakingRewardsManagerImpl::update_rewards` begins with `self.general_prerequisites()` (pause check only) and then checks `current_block_number > self.last_reward_block.read()`. If that passes, it immediately writes `self.last_reward_block.write(current_block_number)` before evaluating `disable_rewards`. When `disable_rewards = true`, the function returns without distributing any rewards. The global gate is now closed for the block; any subsequent call — including the legitimate sequencer call — reverts with `REWARDS_ALREADY_UPDATED`.

The spec states access is "Only starkware sequencer," but no `assert_caller`, role check, or `get_caller_address()` comparison appears anywhere in the function body. [5](#0-4) 

### Impact Explanation
Every block for which the attacker fires first has its entire reward budget silently discarded. Stakers and delegators accumulate zero `unclaimed_rewards_own` for those blocks. Because `last_reward_block` is never rolled back, the loss is permanent — the missed block rewards can never be reclaimed. This matches **High: Permanent freezing of unclaimed yield**.

### Likelihood Explanation
On Starknet the sequencer controls transaction ordering, so in practice the sequencer can always place its own `update_rewards` call ahead of any user transaction in a block it produces. However:
- The sequencer may not call `update_rewards` in every block (e.g., blocks with no eligible staker, or operational gaps).
- A malicious or compromised sequencer node, or a future permissionless sequencer, could exploit this directly.
- The missing guard is a clear spec violation that leaves the invariant unprotected at the contract level.

### Recommendation
Add a caller check at the top of `update_rewards` that asserts `get_caller_address()` equals the designated sequencer address (stored in contract storage), mirroring the pattern used for `update_rewards_from_attestation_contract` which correctly asserts `CALLER_IS_NOT_ATTESTATION_CONTRACT`. [6](#0-5) 

### Proof of Concept
```
// Block N, attacker calls before sequencer:
staking.update_rewards(
    staker_address: any_valid_active_staker,
    disable_rewards: true   // attacker-controlled flag
);
// last_reward_block is now N; no rewards distributed.

// Sequencer's legitimate call in the same block:
staking.update_rewards(staker_address: intended_staker, disable_rewards: false);
// → panics: REWARDS_ALREADY_UPDATED
// Block N rewards are permanently lost for all stakers.
```

Repeat across consecutive blocks to suppress yield indefinitely. [7](#0-6) [8](#0-7)

### Citations

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

**File:** docs/spec.md (L1642-1645)
```markdown
#### pre-condition <!-- omit from toc -->
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
