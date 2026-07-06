### Title
Unprivileged Caller Can Permanently Skip Block Reward Distribution via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

### Summary
`update_rewards` in the `Staking` contract is a public, permissionless function that accepts a caller-controlled `disable_rewards: bool` parameter. The function unconditionally writes `last_reward_block` to the current block number **before** checking `disable_rewards`. Any unprivileged caller can invoke `update_rewards(valid_staker, true)` to permanently consume the per-block reward slot without distributing any rewards, causing that block's yield to be irreversibly lost for all stakers and delegators.

### Finding Description

`IStakingRewardsManager::update_rewards` is declared as a public interface with no role guard: [1](#0-0) 

Inside the implementation, the only access check is `general_prerequisites()`, which only asserts the contract is not paused and the caller is non-zero: [2](#0-1) 

The critical ordering flaw: `last_reward_block` is written to the current block number **before** the `disable_rewards` branch is evaluated: [3](#0-2) 

Once `last_reward_block` is set to the current block, the guard at the top of the function prevents any subsequent call in the same block: [4](#0-3) 

If `disable_rewards` is `true`, the function returns immediately after writing `last_reward_block`, skipping the entire reward calculation and distribution path: [5](#0-4) 

The rewards that would have been distributed via `_update_rewards` — including staker own rewards, commission rewards, and pool rewards — are permanently lost for that block. There is no recovery path.

### Impact Explanation

Every block for which an attacker calls `update_rewards(valid_staker, disable_rewards: true)` results in the permanent loss of that block's STRK (and BTC) rewards for the targeted staker, their delegators, and the commission recipient. Because `last_reward_block` is a single global slot shared across all stakers, one call per block is sufficient to deny rewards to the entire protocol for that block. Repeated across many blocks, this constitutes a sustained, low-cost griefing attack causing **permanent freezing of unclaimed yield**.

This matches the allowed High impact: *"Permanent freezing of unclaimed yield or unclaimed royalties."*

### Likelihood Explanation

The entry path requires only:
1. A non-zero caller address (any EOA or contract).
2. A valid, active staker address with non-zero STRK balance (publicly observable on-chain via `get_stakers` or events).
3. Gas to submit the transaction.

No privileged role, no token balance, no prior relationship with the protocol is needed. The attack is repeatable every block at the cost of a single cheap transaction per block.

### Recommendation

Add an access-control guard to `update_rewards` so that only authorized callers (e.g., the attestation contract, a designated sequencer address, or a role such as `reward_updater`) may invoke it. Alternatively, remove the `disable_rewards` parameter from the public interface entirely and handle the pre-consensus no-op path internally without exposing it as a caller-controlled flag.

### Proof of Concept

1. Attacker observes any active staker address `S` with non-zero STRK balance (e.g., via `get_stakers(current_epoch)`).
2. At the start of block `B`, attacker submits:
   ```
   staking_contract.update_rewards(staker_address: S, disable_rewards: true)
   ```
3. Inside `update_rewards`:
   - `general_prerequisites()` passes (contract not paused, caller non-zero). [6](#0-5) 
   - `current_block_number > last_reward_block` passes (first call this block). [4](#0-3) 
   - Staker validity checks pass. [7](#0-6) 
   - `last_reward_block` is written to block `B`. [8](#0-7) 
   - `disable_rewards == true` → function returns early, no rewards distributed. [9](#0-8) 
4. Any legitimate call to `update_rewards` for block `B` now reverts with `REWARDS_ALREADY_UPDATED`.
5. Block `B`'s rewards are permanently lost. Attacker repeats for every subsequent block.

### Citations

**File:** src/staking/interface.cairo (L303-311)
```text
#[starknet::interface]
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```

**File:** src/staking/staking.cairo (L1448-1460)
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
```

**File:** src/staking/staking.cairo (L1466-1482)
```text
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

**File:** src/staking/staking.cairo (L1484-1507)
```text
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
