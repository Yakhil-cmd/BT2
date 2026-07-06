### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Freeze Staker Yield - (File: src/staking/staking.cairo)

### Summary
`update_rewards` in the Staking contract is documented as callable only by the Starknet sequencer, but the implementation enforces no such restriction. Any unprivileged address can call it with `disable_rewards: true` every block, consuming the global `last_reward_block` slot without distributing rewards, permanently preventing the legitimate sequencer from distributing yield to any staker.

### Finding Description
The `IStakingRewardsManager::update_rewards` function is the consensus-era reward distribution entry point. The spec explicitly states its access control is "Only starkware sequencer." [1](#0-0) 

However, the implementation only calls `general_prerequisites()`, which checks for unpaused state and a non-zero caller — no role check is performed. [2](#0-1) 

`general_prerequisites` is defined as: [3](#0-2) 

The function updates the **global** `last_reward_block` storage variable unconditionally before checking `disable_rewards`: [4](#0-3) 

`last_reward_block` is a single contract-wide value, not per-staker: [5](#0-4) 

When `disable_rewards: true` is passed (or when `is_pre_consensus()` returns true), the function returns immediately after writing `last_reward_block`, distributing zero rewards: [6](#0-5) 

Any subsequent call in the same block — including the legitimate sequencer call — reverts with `REWARDS_ALREADY_UPDATED`: [7](#0-6) 

### Impact Explanation
An attacker who calls `update_rewards(any_valid_active_staker, disable_rewards: true)` once per block permanently prevents reward distribution for every staker in the protocol for that block. Repeating this every block freezes all staker yield indefinitely. This matches the allowed impact: **Permanent freezing of unclaimed yield**.

The attacker gains nothing financially; this is pure griefing. The staker's `unclaimed_rewards_own` is never incremented, and pool rewards are never transferred to delegation pools. [8](#0-7) 

### Likelihood Explanation
- The function is publicly callable (no role guard).
- The attacker only needs one valid active staker address, which is observable on-chain from `NewStaker` events.
- The cost is one cheap transaction per block.
- No special knowledge or capital is required.

### Recommendation
Add a sequencer-only role check at the top of `update_rewards`, analogous to how `update_rewards_from_attestation_contract` restricts callers to the attestation contract: [9](#0-8) 

Introduce and enforce a `only_sequencer` guard (or equivalent role) at the start of `update_rewards`.

### Proof of Concept
1. Deploy the protocol and advance to the consensus rewards epoch.
2. Identify any active staker address `S` with non-zero balance (readable from `NewStaker` events or `staker_info_v3`).
3. From any EOA, call `staking.update_rewards(staker_address: S, disable_rewards: true)` in block `N`.
   - `last_reward_block` is written to `N`; no rewards are distributed.
4. The legitimate sequencer attempts `staking.update_rewards(staker_address: S2, disable_rewards: false)` in the same block `N`.
   - Transaction reverts: `REWARDS_ALREADY_UPDATED`.
5. Repeat step 3 every block. All stakers accumulate zero `unclaimed_rewards_own` indefinitely, and all delegation pools receive zero reward transfers. [10](#0-9)

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

**File:** src/staking/staking.cairo (L1399-1401)
```text
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/staking/staking.cairo (L2361-2375)
```text
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
```
