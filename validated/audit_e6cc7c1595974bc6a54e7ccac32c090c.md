### Title
Unprivileged caller can permanently grief consensus block rewards by calling `update_rewards` with `disable_rewards: true` - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the Staking contract is callable by any unprivileged address and accepts a user-controlled `disable_rewards` boolean. When set to `true`, the function updates the global `last_reward_block` checkpoint but silently skips reward distribution. Because `last_reward_block` is a single global value, this prevents any staker from receiving rewards for that block. An attacker can repeat this every block to permanently freeze all consensus block rewards.

### Finding Description

`update_rewards` is exposed via `IStakingRewardsManager` with no access control beyond `general_prerequisites` (which only checks the contract is unpaused and the caller is non-zero):

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // no role check
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    // Update last block rewards.  <-- written BEFORE the early-return check
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;                    // rewards silently skipped
    }
    ...
    self._update_rewards(...);
}
```

The critical ordering is:
1. `last_reward_block` is written to `current_block_number`.
2. If `disable_rewards == true`, the function returns immediately without calling `_update_rewards`.

Because `last_reward_block` is a **single global storage slot** (not per-staker), any subsequent call to `update_rewards` in the same block will revert with `REWARDS_ALREADY_UPDATED`. The attacker only needs to supply any currently-active staker address (all staker addresses are enumerable via the public `stakers` vector) and pass `disable_rewards: true`. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation

In the consensus rewards phase (`is_pre_consensus() == false`), block rewards are the sole mechanism for distributing STRK to stakers and their delegators. By calling `update_rewards(any_active_staker, true)` once per block, an attacker permanently prevents all stakers from accumulating unclaimed yield. The `last_reward_block` guard ensures only one call succeeds per block, so a single griefing call per block is sufficient to zero out all reward accrual indefinitely.

This matches the allowed impact: **Permanent freezing of unclaimed yield**. [4](#0-3) [5](#0-4) 

### Likelihood Explanation

- The function is publicly callable with no role restriction.
- Active staker addresses are enumerable from the public `stakers` storage vector.
- The only cost to the attacker is gas per block on Starknet (low).
- No special knowledge or privileged access is required.

Likelihood: **Low** (requires sustained per-block transactions, but each is cheap and the attacker gains nothing, making it a pure griefing scenario). [6](#0-5) 

### Recommendation

Restrict `update_rewards` to a trusted caller (e.g., the block proposer / consensus contract), or remove the `disable_rewards` parameter from the public interface and handle the disable logic internally based on an authorised caller check. At minimum, the `last_reward_block` write must not occur before the `disable_rewards` guard, so that a griefing call with `disable_rewards: true` does not consume the per-block slot.

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus() == false`).
2. Attacker monitors the mempool / block production.
3. At every new block N, attacker calls:
   ```
   staking.update_rewards(staker_address=<any_active_staker>, disable_rewards=true)
   ```
4. `last_reward_block` is set to N; `_update_rewards` is never called.
5. Any legitimate call to `update_rewards` in block N reverts with `REWARDS_ALREADY_UPDATED`.
6. No staker or delegator accrues any consensus block rewards for block N.
7. Repeat every block → all unclaimed yield is permanently frozen. [1](#0-0)

### Citations

**File:** src/staking/staking.cairo (L168-170)
```text
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
