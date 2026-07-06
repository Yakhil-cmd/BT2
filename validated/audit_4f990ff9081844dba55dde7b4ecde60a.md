### Title
Unprivileged Caller Can Permanently Suppress Block Rewards via `update_rewards(disable_rewards=true)` — (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in `Staking.cairo` is publicly callable with no access control. It accepts a `disable_rewards: bool` parameter. Critically, the global `last_reward_block` state is written **before** the `disable_rewards` guard is checked. Any unprivileged caller can invoke `update_rewards(staker_address, true)` for any block, permanently consuming that block's reward slot without distributing any rewards to stakers or pools. This is a direct analog to the reported "state recorded but never applied" accounting bug class.

---

### Finding Description

`update_rewards` is the sole mechanism for distributing consensus-mode (V3) block rewards. Its logic is: [1](#0-0) 

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks: not paused, caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    // *** last_reward_block is written HERE, before the disable_rewards check ***
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // exits with NO rewards distributed
    }
    // ... _update_rewards called only if we reach here
```

The `last_reward_block` is a **single global** value. Once it is set to `current_block_number`, the assertion `current_block_number > self.last_reward_block.read()` will fail for every subsequent call in the same block, for every staker. The block's reward slot is permanently consumed. [2](#0-1) 

When `disable_rewards = true`, `_update_rewards` is never reached, so:
- `reward_supplier_dispatcher.update_unclaimed_rewards_from_staking_contract` is never called
- `staker_info.unclaimed_rewards_own` is never incremented
- Pool rewards are never transferred [3](#0-2) 

The rewards for that block are permanently lost — they are never created in the reward supplier and never credited to any staker or pool.

The `general_prerequisites` check imposes no caller restriction: [4](#0-3) 

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
```

Any non-zero address can call `update_rewards(any_active_staker, true)`.

---

### Impact Explanation

This matches **High: Permanent freezing of unclaimed yield**.

In consensus mode (V3), `update_rewards` is the only path through which block rewards are credited. An attacker who calls `update_rewards(staker, true)` for block `N`:

1. Sets `last_reward_block = N` globally.
2. Prevents any further call to `update_rewards` for block `N` (all revert with `REWARDS_ALREADY_UPDATED`).
3. Causes all stakers and their delegation pools to permanently lose the block rewards for block `N`.

The attack can be repeated every block at the cost of gas only, continuously suppressing all consensus reward distribution across the entire protocol.

---

### Likelihood Explanation

- Entry point is fully public (`IStakingRewardsManager`, `#[abi(embed_v0)]`).
- No privileged role, no signature, no stake required.
- The attacker only needs to know any active staker address (publicly observable from `NewStaker` events or the `stakers` vector).
- The attack is repeatable every block with a single transaction.

---

### Recommendation

Move the `last_reward_block` write to **after** the `disable_rewards` guard, so a no-op call does not consume the block slot:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
// Only mark the block as processed when rewards are actually distributed.
self.last_reward_block.write(current_block_number);
// ... proceed with _update_rewards
```

Alternatively, restrict `update_rewards` to a privileged caller (e.g., the attestation contract or a designated rewards manager role) so that the `disable_rewards` path cannot be triggered by an arbitrary address.

---

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. A new block `N` is produced (`N > last_reward_block`).
3. Attacker calls `staking.update_rewards(any_active_staker, true)`.
4. `last_reward_block` is set to `N`; no rewards are distributed.
5. Any legitimate call to `update_rewards` for block `N` now reverts with `REWARDS_ALREADY_UPDATED`.
6. All stakers and pools receive zero rewards for block `N`.
7. Attacker repeats step 3 for every subsequent block, permanently halting all consensus reward distribution. [1](#0-0) [5](#0-4)

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
