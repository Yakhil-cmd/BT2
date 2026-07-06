### Title
Missing Access Control on `update_rewards` Allows Any Caller to Force Reward Distribution - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in `StakingRewardsManagerImpl` is specified to be callable only by the Starkware sequencer, but no caller check is implemented. Any unprivileged address can call it with `disable_rewards: false`, forcing reward minting for any staker on any block — including blocks where the sequencer would have passed `disable_rewards: true` to withhold rewards.

### Finding Description
The specification explicitly states:

> **access control**: Only starkware sequencer. [1](#0-0) 

However, the implementation of `update_rewards` in `StakingRewardsManagerImpl` contains no caller validation whatsoever: [2](#0-1) 

The only guard is a per-block deduplication check (`current_block_number > self.last_reward_block`), which prevents double-calls within the same block but does not restrict *who* can call. A grep for `only_sequencer`, `ONLY_SEQUENCER`, or `sequencer` across all staking source files returns zero matches, confirming the check is entirely absent.

The `IStakingRewardsManager` interface definition also carries no access-control annotation: [3](#0-2) 

When `update_rewards` executes with `disable_rewards: false` in the consensus-rewards phase, it:
1. Calls `reward_supplier.update_current_epoch_block_rewards()` to compute block rewards from the minting curve.
2. Calls `_update_rewards`, which calls `reward_supplier.update_unclaimed_rewards_from_staking_contract(rewards)`, inflating the unclaimed-rewards counter and triggering L1 mint requests via `request_funds`.
3. Transfers STRK rewards to the staker and their delegation pools. [4](#0-3) 

### Impact Explanation
The sequencer uses `disable_rewards: true` for blocks where a staker did not attest, intentionally withholding rewards. An attacker who calls `update_rewards(staker_address, disable_rewards: false)` before the sequencer can do so forces reward distribution for that block, granting the staker STRK rewards they did not earn. This constitutes **theft of unclaimed yield**: tokens are minted from L1 and transferred to the staker/pool without the staker having performed the required attestation work.

### Likelihood Explanation
The function is publicly callable on-chain with no authentication. Any address can submit the transaction. The only rate-limit is one call per block (global `last_reward_block`). An attacker monitoring the mempool can front-run the sequencer's `disable_rewards: true` call every block, consistently stealing rewards for a chosen staker. The attack requires no special privileges, no capital, and no external dependencies.

### Recommendation
Add a caller check at the top of `update_rewards` that asserts the caller is the designated sequencer address (stored in contract storage), mirroring the pattern used in `update_current_epoch_block_rewards` and `update_unclaimed_rewards_from_staking_contract` which both assert `get_caller_address() == staking_contract`. [5](#0-4) 

### Proof of Concept
1. Deploy the system and advance past `consensus_rewards_first_epoch` so consensus rewards are active.
2. A staker stakes and their stake becomes effective (after K epochs).
3. On a new block, before the sequencer submits its transaction, an attacker calls:
   ```
   IStakingRewardsManagerDispatcher { contract_address: staking_contract }
       .update_rewards(staker_address: victim_staker, disable_rewards: false);
   ```
4. The call succeeds (no access control check), `last_reward_block` is updated to the current block, and block rewards are minted and credited to `victim_staker.unclaimed_rewards_own`.
5. The sequencer's subsequent call with `disable_rewards: true` reverts with `REWARDS_ALREADY_UPDATED`.
6. The staker claims the unearned rewards via `claim_rewards`. [6](#0-5)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1448-1458)
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

**File:** src/staking/staking.cairo (L2348-2362)
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
```

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

**File:** src/reward_supplier/reward_supplier.cairo (L166-172)
```text
        fn update_current_epoch_block_rewards(ref self: ContractState) -> (Amount, Amount) {
            let staking_contract = self.staking_contract.read();
            assert!(
                get_caller_address() == staking_contract,
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );
```
