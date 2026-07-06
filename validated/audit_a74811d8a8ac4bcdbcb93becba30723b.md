### Title
Unprivileged Caller Can Permanently Freeze Consensus Rewards by Calling `update_rewards` with `disable_rewards: true` — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the `Staking` contract is callable by any non-zero address. When called with `disable_rewards: true`, it consumes the per-block reward slot (by writing `current_block_number` to the global `last_reward_block`) without distributing any rewards. Because only one `update_rewards` call is permitted per block, an attacker can call this every block to permanently prevent all stakers from receiving consensus rewards.

---

### Finding Description

`update_rewards` is defined in `StakingRewardsManagerImpl` and is the sole entry point for distributing per-block consensus rewards to stakers. [1](#0-0) 

The function enforces a single-call-per-block invariant via `last_reward_block`: [2](#0-1) 

After validating the staker, it unconditionally writes the current block number to `last_reward_block` **before** checking `disable_rewards`: [3](#0-2) 

When `disable_rewards` is `true`, the function returns immediately after that write, distributing nothing: [4](#0-3) 

The only access guard is `general_prerequisites`, which only checks that the contract is not paused and the caller is non-zero: [5](#0-4) 

There is no role check, no allowlist, and no restriction on who may supply `disable_rewards: true`. Any externally-owned address can call `update_rewards(any_active_staker, disable_rewards: true)` in every block, consuming the reward slot without distributing rewards. Every subsequent legitimate call in the same block reverts with `REWARDS_ALREADY_UPDATED`.

The block rewards that would have been distributed are calculated in `calculate_block_rewards` and passed to `_update_rewards`, which calls `update_unclaimed_rewards_from_staking_contract` and transfers STRK to pools and stakers: [6](#0-5) [7](#0-6) 

None of this executes when `disable_rewards: true` short-circuits the function.

---

### Impact Explanation

This is **permanent freezing of unclaimed yield** (High). Every block's reward slot is consumed by the attacker before the legitimate consensus layer can act. Stakers and pool members accumulate zero `unclaimed_rewards_own` and pool `cumulative_rewards_trace` entries are never updated. The frozen yield is never recoverable for those blocks. All participants — stakers, delegators, and pool members — are denied their earned rewards indefinitely.

---

### Likelihood Explanation

High. The attack requires:
- No capital or stake
- No privileged role or leaked key
- Only a non-zero caller address and knowledge of any one active staker address (publicly readable from the `stakers` vector)

The attacker simply front-runs the consensus layer's `update_rewards` call in every block with `disable_rewards: true`. This is trivially automatable.

---

### Recommendation

Restrict `update_rewards` to an authorized caller (e.g., a dedicated consensus-layer role or the attestation contract address). Add a role check analogous to `assert_caller_is_attestation_contract` used in `update_rewards_from_attestation_contract`: [8](#0-7) 

Alternatively, separate the `disable_rewards: true` path into a distinct, role-gated function so that the reward-distribution path and the reward-suppression path have independent access controls.

---

### Proof of Concept

1. Attacker identifies any active staker address (readable from the public `stakers` storage vector).
2. Each block, before the consensus layer submits its `update_rewards` transaction, the attacker submits: `staking.update_rewards(active_staker_address, disable_rewards: true)`.
3. `last_reward_block` is set to the current block number; no rewards are distributed.
4. The consensus layer's legitimate call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeating this every block permanently freezes all consensus reward accrual for every staker and pool member in the protocol.

The structural analog to the external report: in the Li.Fi bug, `msg.value` (a fixed per-call value) was re-sent on every loop iteration, draining the contract of more funds than it received. Here, the per-block reward slot (a fixed resource consumed once per block) is silently consumed on every block by an unprivileged caller with `disable_rewards: true`, draining stakers of all yield they are entitled to receive.

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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/staking/staking.cairo (L2219-2225)
```text
        fn assert_caller_is_attestation_contract(self: @ContractState) {
            assert!(
                get_caller_address() == self.attestation_contract.read(),
                "{}",
                Error::CALLER_IS_NOT_ATTESTATION_CONTRACT,
            );
        }
```

**File:** src/staking/staking.cairo (L2348-2365)
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
```
