### Title
Unprivileged Caller Can Permanently Deny Block Rewards via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in `StakingRewardsManagerImpl` has no caller access control. Any address can invoke it with `disable_rewards: true`, which advances the global `last_reward_block` checkpoint without distributing any rewards. Because only one `update_rewards` call can succeed per block (enforced by the global `last_reward_block` guard), an attacker can permanently consume every block's reward slot, denying all stakers their consensus-era block rewards indefinitely.

### Finding Description
`update_rewards` is a public ABI function gated only by `general_prerequisites()`, which checks that the contract is not paused and the caller is not the zero address. [1](#0-0) 

Inside the function, after validating that the staker exists and has a non-zero balance, the contract unconditionally writes the current block number to the global `last_reward_block` storage slot: [2](#0-1) 

If `disable_rewards` is `true`, the function returns immediately after that write, distributing nothing. The global guard at the top of the function then prevents any further `update_rewards` call in the same block: [3](#0-2) 

`last_reward_block` is a single global field, not per-staker: [4](#0-3) 

An attacker who calls `update_rewards(any_valid_staker_address, disable_rewards: true)` in block `N` therefore:
1. Advances `last_reward_block` to `N`.
2. Distributes zero rewards.
3. Causes every subsequent `update_rewards` call in block `N` to revert with `REWARDS_ALREADY_UPDATED`.

Valid staker addresses are publicly enumerable from the `stakers` vector and from on-chain events (`NewStaker`), so the attacker has no difficulty supplying a valid `staker_address`. [5](#0-4) 

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

In the V3 consensus-rewards era (`is_pre_consensus()` returns `false`), block rewards are the sole mechanism by which stakers and their delegators accumulate `unclaimed_rewards_own` and pool rewards. Each block's reward is computed once and never retroactively recalculated. If `last_reward_block` is advanced without distributing rewards, that block's reward is permanently lost — it cannot be claimed later. An attacker repeating this every block denies all stakers and all delegators their entire yield stream indefinitely, constituting permanent freezing of unclaimed yield.

### Likelihood Explanation
**Medium.**

The attack requires:
- Knowing at least one valid, active staker address — trivially obtained from public on-chain events or the `stakers` vector.
- Submitting one transaction per block before the legitimate `update_rewards` call.

No funds, no privileged role, and no special knowledge beyond a valid staker address are needed. The cost is only gas per block. Automated bots can sustain this indefinitely.

### Recommendation
Restrict who may call `update_rewards` with `disable_rewards: true`, or remove the `disable_rewards` parameter from the public interface entirely. The simplest fix is to require that the caller is either the staker itself, the staker's operational address, or a designated authorized contract (e.g., the attestation contract). Alternatively, split the function into two: one permissionless path that always distributes rewards, and one restricted path for administrative disabling.

### Proof of Concept

1. Staker `S` is registered and active with a non-zero STRK balance. The protocol is in the consensus-rewards era (`is_pre_consensus() == false`).
2. At the start of block `N`, attacker `A` (any EOA) calls:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
3. Inside `update_rewards`:
   - `current_block_number (N) > last_reward_block` → passes.
   - Staker `S` exists and is active → passes.
   - `last_reward_block` is written to `N`.
   - `disable_rewards == true` → function returns; no rewards distributed.
4. Later in block `N`, staker `S` (or anyone on their behalf) calls:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: false)
   ```
5. `current_block_number (N) > last_reward_block (N)` → **false** → reverts with `REWARDS_ALREADY_UPDATED`.
6. Block `N`'s reward for staker `S` (and all other stakers, since the slot is consumed) is permanently lost.
7. Attacker repeats step 2 every block, permanently denying all stakers their yield. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L167-170)
```text
        /// Vector of staker addresses.
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
        /// Map token address to its decimals.
```

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1448-1507)
```text
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
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
