### Title
Unprivileged Caller Can Suppress All Consensus Block Rewards via Unguarded `disable_rewards` Parameter in `update_rewards` — (File: src/staking/staking.cairo)

### Summary

`update_rewards` in `StakingRewardsManagerImpl` is a public function that accepts a caller-controlled `disable_rewards: bool` parameter. When set to `true`, the function still writes the current block number to the global `last_reward_block` storage slot — consuming the one-call-per-block budget — but skips all reward distribution. Because `last_reward_block` is global (not per-staker), a single call with `disable_rewards: true` blocks every other staker from receiving rewards for that block. Any unprivileged, non-zero address can repeat this every block to permanently freeze all consensus yield.

### Finding Description

`update_rewards` is defined in `StakingRewardsManagerImpl` and is gated only by `general_prerequisites()`:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [1](#0-0) 

The function body then unconditionally writes `current_block_number` to `last_reward_block` **before** checking `disable_rewards`:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [2](#0-1) 

The guard that prevents a second call in the same block is:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [3](#0-2) 

Because `last_reward_block` is a single global slot, one call with `disable_rewards: true` for **any** active staker exhausts the per-block reward slot for **all** stakers. No constraint exists that restricts who may pass `disable_rewards: true`.

The WOOFi analog: in WOOFi the missing constraint was `woopool_quote.token_mint == woopool_quote.quote_token_mint` (quote pool must be self-referential). Here the missing constraint is that only an authorized caller (e.g., the attestation contract or a sequencer role) may set `disable_rewards: true`. Both are partial-validation bugs where an unprivileged actor supplies a parameter value that bypasses a critical accounting step.

### Impact Explanation

An attacker calling `update_rewards(any_active_staker, disable_rewards: true)` once per block:

1. Marks the block as "rewards already updated" — no legitimate call can succeed in the same block.
2. Skips `_update_rewards`, so no STRK block rewards are distributed to any staker or delegation pool.

Done continuously, this permanently freezes all consensus-era unclaimed yield for every staker and every pool member in the protocol. This maps to the **High** allowed impact: *Permanent freezing of unclaimed yield*. [4](#0-3) 

### Likelihood Explanation

- No privileged role, leaked key, or special condition is required.
- Any non-zero Starknet address can call `update_rewards`.
- The attacker needs one transaction per block; on Starknet this is cheap relative to the yield stolen from all stakers.
- The attack is reachable as soon as `consensus_rewards_first_epoch` is set (i.e., `is_pre_consensus()` returns `false`). [5](#0-4) 

### Recommendation

Add a constraint that only an authorized caller (e.g., the attestation contract, or a dedicated role) may invoke `update_rewards` with `disable_rewards: true`. The simplest fix is to remove `disable_rewards` from the public interface entirely and handle the "skip rewards" logic internally based on on-chain state, or to gate the parameter behind a role check:

```cairo
if disable_rewards {
    self.roles.only_rewards_manager(); // new role
}
```

Alternatively, split the function into two: a public `update_rewards` (always distributes) and a privileged `update_rewards_disabled` (skips distribution).

### Proof of Concept

1. Protocol enters consensus mode (`is_pre_consensus()` returns `false`).
2. Attacker (any non-zero address) calls, in every block:
   ```
   staking.update_rewards(
       staker_address = <any active staker>,
       disable_rewards = true
   )
   ```
3. Each call writes `last_reward_block = current_block` and returns early — no rewards distributed.
4. Any legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. All stakers and pool members accumulate zero consensus rewards indefinitely. [4](#0-3)

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
