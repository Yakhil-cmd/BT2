### Title
Unprivileged Caller Can Permanently Freeze Staker Rewards via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

### Summary
`IStakingRewardsManager::update_rewards` is a public function with no caller access control. It accepts a caller-controlled `disable_rewards` boolean. When called with `disable_rewards: true`, it writes the current block number to the global `last_reward_block` storage slot **before** checking the flag, then returns without distributing any rewards. Because `last_reward_block` is a single global gate, any subsequent legitimate call in the same block is rejected with `REWARDS_ALREADY_UPDATED`. An unprivileged attacker can call this every block to permanently freeze unclaimed yield for all stakers.

### Finding Description
`StakingRewardsManagerImpl::update_rewards` is exposed with no role guard beyond `general_prerequisites()`, which only checks the contract is unpaused and the caller is non-zero. [1](#0-0) 

The function unconditionally writes `current_block_number` to `last_reward_block` before evaluating `disable_rewards`: [2](#0-1) 

After that write, the early-return branch fires when `disable_rewards` is `true`: [3](#0-2) 

The gate that prevents double-execution in the same block is: [4](#0-3) 

Because `last_reward_block` is a single global slot (not per-staker), one attacker call per block with `disable_rewards: true` exhausts the per-block reward slot for **every** staker. The `general_prerequisites` guard provides no protection: [5](#0-4) 

### Impact Explanation
Every block in which the attacker fires the call, zero rewards are credited to any staker. Repeated across epochs this constitutes **permanent freezing of unclaimed yield** for all stakers and their delegators. No funds are directly stolen, but accrued yield is silently destroyed. This matches the allowed impact: *"High: Permanent freezing of unclaimed yield or unclaimed royalties."*

### Likelihood Explanation
- The attacker only needs any valid, active staker address (trivially obtained from on-chain `NewStaker` events or the public `stakers` vector).
- The call costs only gas; on Starknet L2 this is negligible.
- No privileged key, bridge access, or external dependency is required.
- The attack is fully permissionless and can be automated with a simple bot.

### Recommendation
Restrict `update_rewards` to a trusted caller. The two natural options are:

1. **Restrict to the staker themselves or a designated keeper role** — add `assert!(get_caller_address() == staker_address || self.roles.is_keeper(get_caller_address()))` before the `last_reward_block` write.
2. **Remove the `disable_rewards` parameter from the public interface** — if skipping reward distribution is needed, expose a separate privileged function or derive the flag internally from protocol state (e.g., `is_pre_consensus()`).

Additionally, consider moving the `last_reward_block.write` to **after** the `disable_rewards` guard so that a no-op call does not consume the per-block slot.

### Proof of Concept

```
// Attacker bot, runs every block:
// 1. Read any active staker address S from on-chain events.
// 2. Call staking_contract.update_rewards(staker_address: S, disable_rewards: true)
//    - general_prerequisites() passes (contract unpaused, caller != 0)
//    - current_block_number > last_reward_block  → passes (first call this block)
//    - last_reward_block := current_block_number  ← global slot consumed
//    - disable_rewards == true → early return, no rewards distributed
// 3. Any legitimate staker/keeper call to update_rewards in the same block now hits:
//    assert!(current_block_number > last_reward_block)  → PANICS with REWARDS_ALREADY_UPDATED
// 4. Repeat next block → all stakers receive zero rewards indefinitely.
``` [6](#0-5)

### Citations

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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
