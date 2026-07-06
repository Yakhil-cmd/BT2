### Title
Missing Access Control on `update_rewards` Allows Anyone to Permanently Deny Block Rewards to Stakers - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the Staking contract is documented as restricted to "Only starkware sequencer" but has no access control enforcement in the implementation. Any unprivileged caller can invoke it with `disable_rewards: true`, which advances `last_reward_block` without distributing rewards. Because the per-block guard then prevents any subsequent call for the same block, the staker permanently loses that block's rewards.

### Finding Description
The specification for `update_rewards` explicitly states:

> **Access control:** Only starkware sequencer. [1](#0-0) 

However, the implementation in `StakingRewardsManagerImpl` contains no such check: [2](#0-1) 

The function first writes `current_block_number` to `last_reward_block`, then conditionally skips reward distribution if `disable_rewards` is `true`: [3](#0-2) 

Once `last_reward_block` is set to the current block, any subsequent call for the same block — including the legitimate sequencer call — reverts with `REWARDS_ALREADY_UPDATED`: [4](#0-3) 

The attacker only needs to know a valid active staker address (publicly readable from `get_stakers`) and call `update_rewards(staker_address, disable_rewards: true)` in any block before the sequencer does.

### Impact Explanation
Each block for which `update_rewards` is called with `disable_rewards: true` results in the staker receiving zero block rewards for that block. The `last_reward_block` storage slot is permanently advanced, so the missed rewards can never be recovered. This constitutes **permanent freezing of unclaimed yield** for the targeted staker (and their delegators, since pool rewards are also skipped). [5](#0-4) 

### Likelihood Explanation
The entry point is fully public — no token, key, or privileged role is required. Any address can call `update_rewards` on any active staker. The only prerequisite is that the attacker's transaction lands in the block before the sequencer's legitimate `update_rewards` call. On Starknet, transaction ordering is controlled by the sequencer, but the sequencer may include user transactions before its own protocol transactions, and the attacker can submit the griefing call in every block at negligible cost.

### Recommendation
Add an access-control guard matching the specification. Introduce a `only_sequencer` check (analogous to the existing `only_app_governor` / `only_token_admin` patterns) and apply it at the top of `update_rewards`:

```cairo
fn update_rewards(...) {
    self.roles.only_sequencer(); // enforce spec: "Only starkware sequencer"
    self.general_prerequisites();
    ...
}
```

Alternatively, restrict the `IStakingRewardsManager` interface so that `update_rewards` is only callable from a whitelisted sequencer address stored in contract storage.

### Proof of Concept

1. Deploy the system and advance past the consensus rewards first epoch so rewards are active.
2. As an unprivileged address (not the sequencer), call:
   ```
   staking.update_rewards(victim_staker_address, disable_rewards: true)
   ```
3. Observe that `last_reward_block` is now set to the current block number and no rewards were credited to the staker.
4. The sequencer's subsequent `update_rewards(victim_staker_address, disable_rewards: false)` call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. The staker's `unclaimed_rewards_own` is unchanged — the block's rewards are permanently lost. [6](#0-5)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
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
