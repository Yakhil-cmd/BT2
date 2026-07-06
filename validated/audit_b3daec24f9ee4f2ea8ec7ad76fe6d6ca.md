### Title
Unprivileged Caller Can Permanently Freeze Per-Block Reward Distribution via `update_rewards(disable_rewards=true)` - (File: src/staking/staking.cairo)

### Summary
`update_rewards` is a public function callable by any address. It unconditionally writes `last_reward_block` to the current block **before** checking the `disable_rewards` flag. Any unprivileged caller can invoke `update_rewards(staker_address, disable_rewards=true)` every block, consuming the per-block reward slot without distributing any rewards, and permanently blocking legitimate reward distribution for that block.

### Finding Description
In `StakingRewardsManagerImpl::update_rewards`, the state variable `last_reward_block` is committed to storage at line 1485 before the early-return guard at line 1487:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // ← slot consumed here

if disable_rewards || self.is_pre_consensus() {        // ← guard checked after
    return;
}
``` [1](#0-0) 

The function enforces a strict one-call-per-block invariant:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [2](#0-1) 

Because `last_reward_block` is written before the `disable_rewards` branch, a caller who passes `disable_rewards = true` permanently exhausts the reward slot for that block. No subsequent caller can distribute rewards for the same block, because the `REWARDS_ALREADY_UPDATED` assertion will revert.

The function has no role-based access control beyond `general_prerequisites()` (which only checks pause state and zero-address), so any unprivileged address may call it with any `staker_address` that is currently active. [3](#0-2) 

### Impact Explanation
An attacker who calls `update_rewards(any_active_staker, disable_rewards=true)` once per block permanently destroys the block reward for every staker in the protocol. Because `last_reward_block` is a single global slot shared across all stakers, a single griefing call per block is sufficient to zero out all consensus-phase block rewards indefinitely. This constitutes **permanent freezing of unclaimed yield** for all stakers and delegators.

### Likelihood Explanation
The attack requires only:
1. Knowledge of any currently-active staker address (all staker addresses are emitted as public events via `Events::NewStaker`).
2. One transaction per block, costing only gas.

No privileged role, leaked key, or external dependency is needed. The attack is trivially automatable by a bot.

### Recommendation
Move `last_reward_block.write` to **after** the `disable_rewards` guard, so that a call that skips reward distribution does not consume the block slot:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
// Only mark the block as processed when rewards are actually distributed.
self.last_reward_block.write(current_block_number);
```

Alternatively, restrict who may pass `disable_rewards = true` to a trusted role (e.g., `only_app_governor`), mirroring the access-control pattern used elsewhere in the contract. [4](#0-3) 

### Proof of Concept
1. Staker Alice stakes and becomes active. Her address is public from the `NewStaker` event.
2. At block N, attacker calls `update_rewards(alice_address, disable_rewards=true)`.
3. `last_reward_block` is written to N; the function returns early — no rewards distributed.
4. At block N, any legitimate caller (e.g., the consensus keeper) calls `update_rewards(alice_address, disable_rewards=false)`.
5. The call reverts with `REWARDS_ALREADY_UPDATED` because `current_block_number (N) > last_reward_block (N)` is false.
6. Block N's rewards are permanently lost. Repeating steps 2–5 every block freezes all consensus-phase yield indefinitely. [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L1449-1500)
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
```
