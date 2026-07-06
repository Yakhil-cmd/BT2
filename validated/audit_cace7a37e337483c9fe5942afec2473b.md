### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Destroy Per-Block Staker Rewards - (File: src/staking/staking.cairo)

### Summary

`update_rewards` in the `Staking` contract updates `last_reward_block` **before** distributing rewards, and accepts a caller-controlled `disable_rewards: true` flag that skips distribution entirely. Because the function has no role-based access control — only a "not paused, not zero address" gate — any unprivileged address can call it with `disable_rewards: true` on every block, permanently consuming each block's reward slot without distributing any yield to stakers.

### Finding Description

`update_rewards` is documented in the spec as callable only by the Starkware sequencer:

> **access control**: Only starkware sequencer.

However, the implementation enforces no such restriction. The only gate is `general_prerequisites()`:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [1](#0-0) 

Inside `update_rewards`, the critical ordering is:

1. Validate staker exists and has non-zero balance.
2. **Write `last_reward_block` to the current block number** (line 1485).
3. If `disable_rewards || is_pre_consensus()` → **return early, no rewards distributed**.
4. Otherwise, call `calculate_block_rewards` and `_update_rewards`. [2](#0-1) 

Because `last_reward_block` is committed at step 2, any subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`: [3](#0-2) 

An attacker who calls `update_rewards(active_staker, disable_rewards: true)` first in a block permanently consumes that block's reward slot. `calculate_block_rewards` (which calls `reward_supplier_dispatcher.update_current_epoch_block_rewards()`) is never reached, so no rewards are minted or distributed for that block. The yield is irrecoverably lost. [4](#0-3) 

### Impact Explanation

Every block during the consensus rewards period carries a per-block STRK (and BTC) reward computed from the minting curve. If an attacker front-runs the sequencer's legitimate `update_rewards` call with `disable_rewards: true` on every block, **all staker and pool-member yield is permanently frozen**. The reward supplier never mints those tokens; stakers can never claim them. This matches the allowed impact: **Permanent freezing of unclaimed yield (High)**.

### Likelihood Explanation

Starknet is a public L2. Any EOA or contract can submit a transaction calling `update_rewards`. The attacker only needs to submit a transaction per block with a valid active staker address (publicly readable from the `stakers` vector) and `disable_rewards: true`. No special privilege, leaked key, or external dependency is required. The attack is cheap, repeatable, and fully on-chain.

### Recommendation

Add a sequencer-only role check at the top of `update_rewards`, consistent with the spec's stated access control:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.roles.only_sequencer(); // enforce spec access control
    self.general_prerequisites();
    ...
}
```

Alternatively, restrict `disable_rewards: true` to a privileged role while allowing any caller to invoke the reward-distributing path.

### Proof of Concept

1. Consensus rewards are active (`current_epoch >= consensus_rewards_first_epoch`).
2. Staker `S` has been staked for `K` epochs and has non-zero effective balance.
3. Attacker `A` (any non-zero address) submits a transaction at the start of block `B`:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. Inside `update_rewards`:
   - `general_prerequisites()` passes (not paused, A ≠ 0).
   - `current_block_number (B) > last_reward_block` → passes.
   - Staker S is active with non-zero balance → passes.
   - `last_reward_block` is written to `B`.
   - `disable_rewards == true` → early return; no rewards minted or distributed.
5. The sequencer's legitimate `update_rewards` call for block `B` now reverts with `REWARDS_ALREADY_UPDATED`.
6. Repeating this every block permanently destroys all staker yield. [4](#0-3)

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
