Looking at the `update_rewards` function in `src/staking/staking.cairo`, the spec says "Only starkware sequencer" but the implementation has **no caller check**. Any address can call it with `disable_rewards: true` to consume the block's reward slot without distributing rewards, permanently freezing staker yield.

### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Permanently Freeze Staker Rewards - (File: `src/staking/staking.cairo`)

### Summary
`IStakingRewardsManager::update_rewards` is documented as callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can call it with `disable_rewards: true` on every block, consuming the per-block reward slot without distributing rewards, permanently freezing all staker and delegator yield.

### Finding Description
The spec for `update_rewards` states:

> **access control**: Only starkware sequencer.

However, the implementation in `StakingRewardsManagerImpl` performs no such check:

```cairo
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
    // ... no get_caller_address() check anywhere
    self.last_reward_block.write(current_block_number);
    if disable_rewards || self.is_pre_consensus() {
        return;
    }
    // ... reward distribution only reached if caller cooperates
``` [1](#0-0) 

The function enforces only one call per block via `last_reward_block`, but does not restrict *who* can make that call. An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` on every block:

1. Writes `current_block_number` into `last_reward_block`, consuming the slot.
2. Returns immediately at the `disable_rewards` branch without distributing any rewards.
3. Causes the legitimate sequencer's subsequent call in the same block to revert with `REWARDS_ALREADY_UPDATED`. [2](#0-1) 

The interface definition confirms no access control is enforced in code: [3](#0-2) 

The spec discrepancy is explicit: [4](#0-3) 

### Impact Explanation
Every block where the attacker fires first, stakers and delegators receive zero rewards. Repeated across all blocks, this permanently freezes all unclaimed yield for every staker and every delegation pool. The `unclaimed_rewards_own` field of stakers and the pool balances never increase. This matches the **High** impact category: *Permanent freezing of unclaimed yield*. [5](#0-4) 

### Likelihood Explanation
Starknet L2 gas fees are low. An attacker needs only to submit one transaction per block (calling `update_rewards` with any valid active staker address and `disable_rewards: true`). No funds, no privileged role, and no special setup are required. The attacker can automate this with a simple bot. The attack is economically viable as a pure griefing attack with no profit motive.

### Recommendation
Add a caller check at the top of `update_rewards` to enforce that only the designated sequencer address (or a registered operator role) can invoke it, consistent with the spec:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    // Add: assert caller is the sequencer or a registered rewards operator
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    // ... rest of function
```

Alternatively, expose a separate permissioned role (e.g., `REWARDS_MANAGER_ROLE`) and gate the function on it.

### Proof of Concept

1. Deploy the protocol in consensus-rewards mode with an active staker.
2. At the start of each new block, before the sequencer acts, call:
   ```
   staking.update_rewards(staker_address: any_active_staker, disable_rewards: true)
   ```
3. The call succeeds (no caller check), writes `last_reward_block = current_block`, and returns without distributing rewards.
4. The sequencer's legitimate call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. After N blocks of this, `staker_info.unclaimed_rewards_own` remains zero and all pool balances remain zero, confirming permanent yield freeze. [6](#0-5) [2](#0-1)

### Citations

**File:** src/staking/staking.cairo (L1447-1508)
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
    }
```

**File:** src/staking/staking.cairo (L2348-2365)
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

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```
