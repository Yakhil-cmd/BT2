### Title
Unprivileged Caller Can Permanently Suppress All Consensus Rewards via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

### Summary
`IStakingRewardsManager::update_rewards` is a public, permissionless function that accepts an attacker-controlled `disable_rewards: bool` parameter. Because the function writes to the **global** `last_reward_block` storage slot regardless of the `disable_rewards` value, any unprivileged caller can invoke `update_rewards(any_active_staker, disable_rewards: true)` once per block to consume the single per-block reward slot without distributing any rewards. Repeating this every block permanently prevents all stakers from ever receiving consensus-era block rewards.

### Finding Description
`update_rewards` in `StakingRewardsManagerImpl` performs two unconditional actions before checking `disable_rewards`:

1. It asserts `current_block_number > last_reward_block` (line ~1454–1458).
2. It writes `last_reward_block = current_block_number` (line ~1485).

Only after those two steps does it branch on `disable_rewards`:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;   // ← exits without distributing any rewards
}
``` [1](#0-0) 

`last_reward_block` is a single global storage slot shared across all stakers:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [2](#0-1) 

There is no access-control guard on `update_rewards`; `general_prerequisites()` only checks the pause flag and a non-zero caller:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [3](#0-2) 

The interface confirms the function is fully public with no role restriction:

```cairo
pub trait IStakingRewardsManager<TContractState> {
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
``` [4](#0-3) 

### Impact Explanation
An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` at every block:

- Writes `last_reward_block = current_block_number` without distributing rewards.
- Causes every subsequent legitimate call in the same block to revert with `REWARDS_ALREADY_UPDATED`.
- Because each block's reward window is non-recoverable (past blocks cannot be re-processed), the yield for that block is permanently lost for **all** stakers and delegators.

Sustained over time this constitutes **permanent freezing of unclaimed yield** for the entire protocol — matching the High-severity impact in scope.

### Likelihood Explanation
The entry point is fully public on Starknet L2. The attacker only needs to know one active staker address (trivially obtained from on-chain events or `get_stakers`). The cost is one Starknet transaction per block; at current gas prices this is economically feasible for a motivated griever or a competitor validator. No privileged access, leaked key, or external dependency is required.

### Recommendation
Restrict who may supply `disable_rewards: true`. Two complementary mitigations:

1. **Access control**: Gate `update_rewards` (or at least the `disable_rewards = true` path) behind a role check (e.g., `only_app_governor` or a dedicated `REWARD_UPDATER` role), consistent with how other sensitive parameters are protected.
2. **Separate the paths**: Split the function into `update_rewards` (always distributes, no flag) and a privileged `skip_rewards_for_block` callable only by governance, eliminating the attacker-controlled boolean entirely.

### Proof of Concept

```
// Attacker script — runs once per block
loop {
    let active_staker = staking.get_stakers(current_epoch)[0].staker_address;
    staking.update_rewards(
        staker_address: active_staker,
        disable_rewards: true,   // ← attacker-controlled
    );
    // last_reward_block is now set to current block;
    // any legitimate update_rewards call this block reverts with REWARDS_ALREADY_UPDATED.
    // Rewards for this block are permanently lost for all stakers.
    wait_for_next_block();
}
```

Step-by-step:

1. Attacker calls `update_rewards(active_staker, true)` at block N.
2. `last_reward_block` is written to N; function returns early — zero rewards distributed.
3. Legitimate consensus reward call at block N reverts: `current_block_number (N) > last_reward_block (N)` is false.
4. Block N's rewards are permanently lost.
5. Attacker repeats at block N+1, N+2, … indefinitely.

All stakers and delegators receive zero consensus rewards for the duration of the attack.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
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
