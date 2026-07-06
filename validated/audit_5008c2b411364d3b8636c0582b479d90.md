### Title
Unrestricted `update_rewards` with `disable_rewards=true` Permanently Freezes Consensus Block Rewards for All Stakers — (File: `src/staking/staking.cairo`)

### Summary

`IStakingRewardsManager::update_rewards` is a public, permissionless function that accepts a caller-controlled `disable_rewards: bool` flag. When called with `disable_rewards: true`, it advances the global `last_reward_block` checkpoint to the current block without distributing any rewards. Because `last_reward_block` is a single contract-wide variable, one such call per block permanently forfeits that block's consensus rewards for every staker in the protocol. Any unprivileged address can repeat this every block, causing an indefinite, protocol-wide freeze of unclaimed yield.

### Finding Description

`update_rewards` is exposed as a fully public entrypoint under `IStakingRewardsManager`. Its only gate is `general_prerequisites()`, which checks that the contract is not paused and that the caller is not the zero address — no role, no stake, no identity check. [1](#0-0) 

Inside the function, the very first meaningful state write is to the global `last_reward_block`: [2](#0-1) 

The guard that prevents a second call in the same block reads this same global: [3](#0-2) 

Because `last_reward_block` is a single storage slot shared across all stakers: [4](#0-3) 

a single call with `disable_rewards: true` in block `N` sets `last_reward_block = N` and then returns early before any reward computation: [5](#0-4) 

The rewards that would have been distributed for block `N` are permanently lost — the next valid call can only occur in block `N+1`, and the window for block `N` is closed forever.

The `disable_rewards` flag was designed for the migration path (pre-consensus → consensus), but because the function is public and the flag is caller-controlled, any external actor can weaponize it.

### Impact Explanation

Each suppressed block permanently forfeits that block's share of consensus rewards for all active stakers and their delegators. An attacker who calls `update_rewards(any_valid_staker, true)` once per block causes:

- **Permanent loss of unclaimed yield** for every staker in the protocol for every attacked block.
- The loss compounds linearly with the duration of the attack.
- No recovery is possible for already-skipped blocks; the `last_reward_block` pointer cannot be rewound.

This matches the allowed impact: **High — Permanent freezing of unclaimed yield**.

### Likelihood Explanation

- The function is fully public; no stake, role, or special address is required.
- The attacker only needs to submit one transaction per block, which is cheap on Starknet L2.
- Any party with a financial motive to harm stakers (e.g., a competing validator, a protocol short-seller, or a griever) can sustain the attack indefinitely.
- The attack is invisible to stakers until they notice rewards have stopped accumulating.

### Recommendation

1. **Restrict the caller**: Add an access-control check so that only a trusted role (e.g., `OPERATOR_ROLE`, the sequencer, or the attestation contract) may call `update_rewards`. This mirrors the fix applied to the AuctionCrowdfund `bid()` function (restricting it to hosts/members).
2. **Remove the `disable_rewards` flag from the public interface**: If the flag is needed only during migration, expose it only through an internal function or a privileged migration entrypoint.
3. **Per-staker `last_reward_block`**: If the function must remain public, scope the block-deduplication guard per `staker_address` rather than globally, so that a call for one staker cannot block reward distribution for all others.

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. Attacker picks any valid, active staker address `S`.
3. At the start of every block `N`, attacker calls:
   ```
   staking_contract.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. The function passes all checks (not paused, caller non-zero, staker active, non-zero balance), writes `last_reward_block = N`, then hits the early-return branch at line 1487.
5. Any legitimate call to `update_rewards` in block `N` (with `disable_rewards: false`) reverts with `REWARDS_ALREADY_UPDATED`.
6. Block `N`'s rewards are permanently lost for all stakers.
7. Attacker repeats step 3 every block. All consensus rewards are frozen indefinitely at a cost of one cheap L2 transaction per block. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1447-1507)
```text
    #[abi(embed_v0)]
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
