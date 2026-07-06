### Title
Permissionless `update_rewards` with `disable_rewards: true` Permanently Freezes Unclaimed Yield - (File: `src/staking/staking.cairo`)

### Summary
Any unprivileged caller can invoke `update_rewards` with `disable_rewards: true` on any valid staker address, consuming the single per-block reward slot (`last_reward_block`) without distributing any rewards. Repeated every block, this permanently freezes yield accrual for all stakers and delegators.

### Finding Description
`IStakingRewardsManager::update_rewards` is a fully permissionless external function. Its only caller-side guards are `general_prerequisites()` (contract not paused, caller non-zero) and a check that `current_block_number > last_reward_block`. The function accepts a caller-supplied `disable_rewards: bool` flag.

The critical ordering is:

```
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // ← written unconditionally

if disable_rewards || self.is_pre_consensus() {
    return;                                            // ← exits before _update_rewards
}
``` [1](#0-0) 

`last_reward_block` is a single global `BlockNumber` in storage, not per-staker. [2](#0-1) 

Because `last_reward_block` is written **before** the `disable_rewards` branch, any caller who passes `disable_rewards: true` with any currently-active staker address will:
1. Advance `last_reward_block` to the current block.
2. Return without calling `_update_rewards`, so no yield is accrued.
3. Cause every subsequent call to `update_rewards` in the same block to revert with `REWARDS_ALREADY_UPDATED`. [3](#0-2) 

The attacker only needs a valid, active staker address with non-zero balance — all of which are publicly observable from on-chain events and the `stakers` vector. [4](#0-3) 

### Impact Explanation
`_update_rewards` is the sole mechanism by which stakers and their delegation pools accumulate `unclaimed_rewards_own` in the consensus-rewards phase. If it is never called, no yield is ever credited. Stakers calling `claim_rewards` would receive zero. Delegators calling `pool.claim_rewards` would also receive zero because the pool's `cumulative_rewards_trace` is never advanced.

This constitutes **permanent freezing of unclaimed yield** for all stakers and delegators — matching the High impact tier.

### Likelihood Explanation
- The function is fully permissionless; no role, stake, or prior registration is required.
- The attacker only needs to submit one transaction per block with any valid staker address (trivially obtained from `NewStaker` events).
- Starknet transaction fees are low, making sustained griefing economically viable.
- The attack is silent: no revert, no anomalous event — just a missing reward update each block.

### Recommendation
Add access control to `update_rewards` so only an authorized caller (e.g., the attestation contract, a designated keeper role, or the staker/their operational address) can invoke it. Alternatively, move the `last_reward_block.write` to after the `disable_rewards` guard so that a no-op call does not consume the block slot:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
self.last_reward_block.write(current_block_number); // moved here
// ... _update_rewards ...
```

### Proof of Concept
1. Staker `S` is registered and active with non-zero STRK balance.
2. Each block, attacker `A` (any EOA) calls:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
3. The call passes all checks, writes `last_reward_block = current_block`, and returns early.
4. Any legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. After repeating for every block, `unclaimed_rewards_own` for all stakers remains zero indefinitely.
6. Stakers and delegators calling `claim_rewards` receive nothing. [3](#0-2) [1](#0-0)

### Citations

**File:** src/staking/staking.cairo (L168-170)
```text
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
        /// Map token address to its decimals.
```

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
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
