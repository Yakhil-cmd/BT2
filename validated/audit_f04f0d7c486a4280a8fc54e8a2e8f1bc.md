### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Block Staker Reward Distribution - (File: `src/staking/staking.cairo`)

### Summary

The `update_rewards` function in the Staking contract is specified to be callable only by the Starkware sequencer, but no on-chain access control enforces this. Any unprivileged caller can invoke `update_rewards(staker_address, disable_rewards: true)`, which marks the current block as processed and returns early without distributing rewards. Because `last_reward_block` is a global singleton, a single such call per block permanently forfeits all stakers' consensus rewards for that block.

### Finding Description

The `IStakingRewardsManager::update_rewards` function is the sole mechanism for distributing per-block consensus rewards to stakers and their delegation pools. The protocol specification explicitly restricts its access:

> **access control**: Only starkware sequencer. [1](#0-0) 

However, the implementation only calls `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero — no sequencer identity check is performed:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();          // only: not paused, caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    self.last_reward_block.write(current_block_number);   // global singleton

    if disable_rewards || self.is_pre_consensus() {
        return;                            // exits before any reward calculation
    }
    ...
}
``` [2](#0-1) 

`general_prerequisites` enforces only two conditions: [3](#0-2) 

The `last_reward_block` field is a single global value shared across all stakers: [4](#0-3) 

Because `disable_rewards` is a caller-supplied boolean, any address can:

1. Call `update_rewards(any_staker_address, disable_rewards: true)` in block N.
2. `last_reward_block` is written to N.
3. The sequencer's subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
4. No staker receives consensus rewards for block N.

Repeating this every block permanently freezes all consensus reward accrual for the entire protocol.

### Impact Explanation

Consensus rewards are the primary yield mechanism for stakers and delegators in the post-attestation phase. Blocking `update_rewards` means `staker_info.unclaimed_rewards_own` is never incremented and pool rewards are never transferred. The yield is permanently lost — it is never credited to `unclaimed_rewards` in the `RewardSupplier`, so it cannot be claimed later. This constitutes **permanent freezing of unclaimed yield** for all stakers and delegators simultaneously. [5](#0-4) 

### Likelihood Explanation

The function is publicly callable with no role check. An attacker needs only a funded Starknet account and the ability to submit a transaction before the sequencer's own `update_rewards` call in any given block. Because the sequencer is a single entity and transaction ordering on Starknet is deterministic, a well-timed or repeated attack can reliably suppress reward distribution. The cost is gas per block; there is no other barrier.

### Recommendation

Add a sequencer-only access control guard, analogous to the pattern used in `update_current_epoch_block_rewards` in the `RewardSupplier`:

```cairo
assert!(
    get_caller_address() == self.sequencer_address.read(),
    "{}",
    GenericError::CALLER_IS_NOT_SEQUENCER,
);
``` [6](#0-5) 

Alternatively, store the sequencer address in the staking contract and enforce it at the top of `update_rewards`, consistent with the specification's stated access control.

### Proof of Concept

```
// Block N begins.
// Attacker (any non-zero address) calls:
staking.update_rewards(staker_address: any_valid_staker, disable_rewards: true);
// → last_reward_block is now N
// → returns early, no rewards distributed

// Sequencer then tries:
staking.update_rewards(staker_address: staker_A, disable_rewards: false);
// → panics: REWARDS_ALREADY_UPDATED (current_block_number == last_reward_block)

// All stakers miss rewards for block N.
// Attacker repeats every block → permanent yield freeze.
```

The `REWARDS_ALREADY_UPDATED` error confirms the block-level singleton lock: [7](#0-6)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```

**File:** src/staking/staking.cairo (L2348-2376)
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
