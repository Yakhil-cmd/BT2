### Title
Unprivileged Caller Can Permanently Suppress Block Rewards for All Stakers via `update_rewards(disable_rewards=true)` — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function unconditionally writes the current block number to the global `last_reward_block` storage slot **before** checking the `disable_rewards` flag. Because `update_rewards` has no role-based access control, any unprivileged caller can invoke it with `disable_rewards=true` to consume a block's reward slot without distributing any rewards, permanently preventing all stakers from receiving consensus rewards for that block.

---

### Finding Description

`update_rewards` (line 1449) is the consensus-era entry point for distributing per-block staking rewards. Its execution order is:

1. `general_prerequisites()` — only checks contract is not paused and caller is non-zero. [1](#0-0) 
2. Assert `current_block_number > last_reward_block` — enforces one call per block. [2](#0-1) 
3. Validate staker exists and is active. [3](#0-2) 
4. **Write `current_block_number` to `last_reward_block`** — unconditionally. [4](#0-3) 
5. **Early return if `disable_rewards || self.is_pre_consensus()`** — no rewards distributed. [5](#0-4) 
6. Calculate and distribute block rewards to staker and pools. [6](#0-5) 

`last_reward_block` is a **global, single-slot** field — not per-staker. [7](#0-6) 

Once it is set to block N, the assertion at step 2 prevents **any** subsequent call in the same block from distributing rewards. Because step 4 executes before step 5, calling `update_rewards(any_valid_staker, disable_rewards=true)` at block N:

- Marks block N as "processed" in `last_reward_block`.
- Distributes **zero** rewards to any staker or pool.
- Makes every legitimate `update_rewards(..., false)` call at block N revert with `REWARDS_ALREADY_UPDATED`.

The root cause is the same class as the canopy-node bug: **primary state (`last_reward_block`) is updated without updating the corresponding secondary state (staker `unclaimed_rewards_own` and pool reward balances)**, leaving the system in a permanently inconsistent state for that block.

The actual reward distribution happens inside `_update_rewards`, which updates `staker_info.unclaimed_rewards_own` and calls `update_pool_rewards`. [8](#0-7) 

---

### Impact Explanation

- Block N's rewards are **permanently lost** — not deferred. There is no mechanism to retroactively distribute rewards for a block whose `last_reward_block` slot has already been consumed.
- Because `last_reward_block` is global, a single attacker call blocks **all stakers** from receiving rewards for that block.
- Repeating this every block permanently denies all consensus rewards to all stakers.
- **Impact: High — Permanent freezing of unclaimed yield.**

---

### Likelihood Explanation

- No privileged role is required. Any non-zero address can call `update_rewards`. [9](#0-8) 
- The attacker only needs to submit a transaction before the legitimate `update_rewards` call in any block. On Starknet, transaction ordering within a sequencer batch is influenced by fee priority, making front-running feasible.
- Cost to attacker: gas fees only. No capital at risk.
- The attack is repeatable every block with negligible effort.
- **Likelihood: High.**

---

### Recommendation

Move `self.last_reward_block.write(current_block_number)` to **after** the `disable_rewards` guard, so the block slot is only consumed when rewards are actually distributed:

```rust
// Update last block rewards ONLY when rewards will be distributed.
if disable_rewards || self.is_pre_consensus() {
    return;
}
self.last_reward_block.write(current_block_number);
// ... proceed with reward calculation
```

Alternatively, add role-based access control to restrict who may call `update_rewards` with `disable_rewards=true` (e.g., restrict to the attestation contract or a trusted consensus role).

---

### Proof of Concept

1. Consensus rewards are active (`current_epoch >= consensus_rewards_first_epoch`).
2. At block N, attacker calls `update_rewards(any_valid_active_staker, disable_rewards=true)`.
3. `last_reward_block` is written to N. No staker or pool receives any reward. [10](#0-9) 
4. Legitimate staker or consensus mechanism calls `update_rewards(staker, false)` at block N → reverts: `current_block_number > self.last_reward_block.read()` is false. [2](#0-1) 
5. Block N's rewards are permanently lost for every staker and every delegation pool.
6. Attacker repeats at block N+1, N+2, … to continuously deny all consensus rewards.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1452-1453)
```text
            self.general_prerequisites();
            let current_block_number = starknet::get_block_number();
```

**File:** src/staking/staking.cairo (L1454-1458)
```text
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
                Error::REWARDS_ALREADY_UPDATED,
            );
```

**File:** src/staking/staking.cairo (L1460-1482)
```text
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
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

**File:** src/staking/staking.cairo (L1491-1506)
```text
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
```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/staking/staking.cairo (L2313-2376)
```text
        fn _update_rewards(
            ref self: ContractState,
            staker_address: ContractAddress,
            strk_total_rewards: Amount,
            btc_total_rewards: Amount,
            strk_total_stake: NormalizedAmount,
            btc_total_stake: NormalizedAmount,
            mut staker_info: InternalStakerInfoLatest,
            staker_pool_info: StoragePath<InternalStakerPoolInfoV2>,
            reward_supplier_dispatcher: IRewardSupplierDispatcher,
            curr_epoch: Epoch,
        ) {
            // Calculate self rewards.
            let staker_own_rewards = self
                .calculate_staker_own_rewards(
                    :staker_address, :strk_total_rewards, :strk_total_stake, :curr_epoch,
                );

            // Calculate pools rewards.
            let (commission_rewards, total_pools_rewards, pools_rewards_data) = if staker_pool_info
                .has_pool() {
                self
                    .calculate_staker_pools_rewards(
                        :staker_address,
                        :staker_pool_info,
                        :strk_total_rewards,
                        :strk_total_stake,
                        :btc_total_rewards,
                        :btc_total_stake,
                        :curr_epoch,
                    )
            } else {
                (Zero::zero(), Zero::zero(), array![])
            };

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
