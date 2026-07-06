### Title
Unprivileged Caller Can Permanently Deny Staker Block Rewards via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the Staking contract is callable by any unprivileged address and accepts a `disable_rewards` boolean parameter. When called with `disable_rewards: true`, the function consumes the per-block reward slot by writing `last_reward_block` but skips all reward distribution. Because only one call per block is permitted, an attacker can front-run the legitimate call to permanently deny block rewards to any staker.

### Finding Description
`update_rewards` (lines 1449–1507 of `src/staking/staking.cairo`) has no caller access control beyond `general_prerequisites` (which only checks the contract is unpaused and the caller is non-zero). The execution order is:

1. Assert `current_block_number > last_reward_block` — only one call per block is allowed.
2. Validate the staker exists and is active.
3. **Write `last_reward_block = current_block_number`** — the slot is consumed unconditionally.
4. If `disable_rewards == true`, **return immediately** — no rewards are computed or distributed. [1](#0-0) [2](#0-1) 

Because `last_reward_block` is updated **before** the `disable_rewards` branch, any external caller can atomically consume the reward slot for the current block while suppressing reward distribution. The legitimate staker (or their operational address) cannot call `update_rewards` again in the same block — the `REWARDS_ALREADY_UPDATED` assertion will revert.

The analog to the sfrxETH report is direct: in sfrxETH, a state-dependent value (`previewMint`) is consumed by a third party before the user's transaction executes, causing the user's expected outcome to be denied. Here, the per-block reward slot (`last_reward_block`) is consumed by an unprivileged caller with `disable_rewards: true`, causing the staker's expected block reward to be denied.

### Impact Explanation
An attacker who calls `update_rewards(staker_address, true)` once per block for a target staker causes that staker to receive **zero block rewards** for every block the attacker acts. This constitutes continuous theft of unclaimed yield. The staker's `unclaimed_rewards_own` is never incremented, and pool members also receive no rewards for those blocks. The loss is permanent — missed block rewards are not retroactively compensated. [3](#0-2) 

### Likelihood Explanation
The attack requires no special privilege — only a non-zero caller address and enough gas. It is fully automatable: a bot can watch the mempool and front-run every legitimate `update_rewards` call, or simply submit `update_rewards(target, true)` as the first transaction of every block. The attacker has no profit motive but the cost is only gas, making targeted griefing of competing validators economically rational.

### Recommendation
Restrict who may pass `disable_rewards: true`. The simplest fix is to require that the caller is the staker themselves or their registered operational/reward address when `disable_rewards` is `true`. Alternatively, remove the `disable_rewards` parameter from the public interface entirely and handle the pre-consensus no-op path internally.

```cairo
if disable_rewards {
    assert!(
        caller == staker_address || caller == staker_info.operational_address,
        "{}",
        Error::UNAUTHORIZED_DISABLE_REWARDS,
    );
}
```

### Proof of Concept

1. Staker A is active with a non-zero STRK balance in the current epoch.
2. At the start of block N, attacker calls `update_rewards(staker_A_address, disable_rewards: true)`.
3. The contract writes `last_reward_block = N` and returns early — no rewards distributed.
4. Staker A (or anyone else) attempts `update_rewards(staker_A_address, false)` in block N — reverts with `REWARDS_ALREADY_UPDATED`.
5. Staker A receives zero block rewards for block N.
6. Attacker repeats every block; staker A's `unclaimed_rewards_own` never increases. [4](#0-3)

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
