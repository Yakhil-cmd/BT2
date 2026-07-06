### Title
Unprivileged Caller Can Permanently Deny All Stakers Block Rewards via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

### Summary
The public `update_rewards` function in `staking.cairo` accepts a `disable_rewards` boolean parameter. When set to `true`, the function updates the global `last_reward_block` storage variable without distributing any rewards. Because `last_reward_block` is a single global lock and the function has no access control beyond a basic unpaused/non-zero-caller check, any unprivileged caller can invoke it every block to permanently consume each block's reward slot, denying all stakers their consensus block rewards.

### Finding Description
`update_rewards` is a publicly callable function with no role-based access control. Its only guards are `general_prerequisites()` (unpaused + non-zero caller) and a check that the current block number exceeds `last_reward_block`.

The critical sequence inside the function is:

1. The staker is validated as active with non-zero balance.
2. `last_reward_block` is unconditionally written to the current block number.
3. If `disable_rewards == true`, the function returns immediately — no rewards are calculated or distributed. [1](#0-0) 

Because `last_reward_block` is a **global** variable shared across all stakers, once it is updated for block `N`, the assertion at line 1454–1458 causes every subsequent `update_rewards` call in block `N` to revert with `REWARDS_ALREADY_UPDATED`. [2](#0-1) 

`general_prerequisites` imposes no role check: [3](#0-2) 

An attacker therefore only needs a valid, active staker address (trivially obtained from on-chain `NewStaker` events) to call `update_rewards(valid_staker, disable_rewards: true)` at the start of every block, permanently consuming each block's reward slot without distributing anything.

### Impact Explanation
This is a **permanent freezing of unclaimed yield** for all stakers. In the consensus rewards model (V3), each block produces STRK and BTC block rewards calculated by `calculate_block_rewards` and distributed via `_update_rewards`. If `disable_rewards: true` is injected every block, `_update_rewards` is never reached, `update_unclaimed_rewards_from_staking_contract` is never called on the reward supplier, and no staker ever accrues rewards. The yield is not merely delayed — it is permanently lost because block rewards are computed per-block and there is no catch-up mechanism. [4](#0-3) 

### Likelihood Explanation
High. The attacker requires:
- One valid, active staker address with non-zero balance (publicly observable from events).
- The ability to submit one transaction per block.

Starknet transaction fees are low. A griefing attacker (e.g., a competing validator or protocol adversary) can sustain this indefinitely. No privileged access, leaked key, or external dependency is required.

### Recommendation
Restrict `update_rewards` so that only the staker themselves (or a designated trusted caller such as the attestation contract) may invoke it. Alternatively, remove the `disable_rewards` parameter entirely and rely solely on `is_pre_consensus()` to gate reward distribution, since that check already handles the pre-consensus phase:

```cairo
fn update_rewards(ref self: ContractState, staker_address: ContractAddress) {
    // Remove disable_rewards parameter; access-control or remove entirely.
    ...
    if self.is_pre_consensus() {
        return;
    }
    ...
}
```

### Proof of Concept
1. Attacker observes any `NewStaker` event to obtain a valid `staker_address`.
2. Each block, attacker submits: `staking.update_rewards(staker_address, disable_rewards: true)`.
3. `last_reward_block` is set to the current block number at line 1485.
4. The function returns at line 1487 without calling `_update_rewards`.
5. Any legitimate `update_rewards` call in the same block hits the assertion at line 1454–1458 and reverts.
6. No staker receives block rewards for that block.
7. Repeated every block → all stakers permanently lose all consensus block rewards. [5](#0-4)

### Citations

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
