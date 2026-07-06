### Title
Front-Running `update_rewards` via Global `last_reward_block` Causes Reward Update Griefing — (File: src/staking/staking.cairo)

---

### Summary
The `update_rewards` function in the `Staking` contract enforces a one-update-per-block rule using a **single global** `last_reward_block` storage variable. Because the function is callable by any non-zero address for any valid staker, an attacker can front-run a legitimate `update_rewards` call by submitting their own call first (for any valid staker), setting `last_reward_block` to the current block and causing all subsequent `update_rewards` calls in that block to revert with `REWARDS_ALREADY_UPDATED`.

---

### Finding Description

`update_rewards` in `IStakingRewardsManager` has no caller access control beyond `general_prerequisites()`, which only checks that the contract is unpaused and the caller is non-zero: [1](#0-0) 

The global guard is a single storage slot: [2](#0-1) 

After the guard passes, `last_reward_block` is immediately written to the current block number: [3](#0-2) 

Because `last_reward_block` is **global** (not per-staker), a single successful call for *any* valid staker in block N locks out every other `update_rewards` call for the remainder of that block. The function signature accepts an arbitrary `staker_address`: [4](#0-3) 

An attacker needs only to pick any currently-active staker and submit the call with a higher gas price (or earlier in the block ordering) to win the race.

---

### Impact Explanation

**Medium — Griefing with no profit motive but damage to users or protocol.**

- Every `update_rewards` call that loses the race reverts with `REWARDS_ALREADY_UPDATED`.
- The consensus mechanism (or staker) that submitted the legitimate call wastes gas and misses the reward update for that block.
- Because `calculate_block_rewards` is epoch-scoped and the missed block's reward slot is not retroactively applied, a staker whose update is repeatedly front-run across many blocks accumulates a deficit in `unclaimed_rewards_own` relative to what they should have earned.
- The attacker gains nothing; the damage is pure griefing of the reward-update liveness. [5](#0-4) 

---

### Likelihood Explanation

**Medium.** On Starknet the sequencer orders transactions within a block. An attacker monitoring pending transactions can submit a `update_rewards` call for any live staker with a marginally higher fee to be ordered first. The attack requires no privileged access, no signed data, and no special knowledge beyond the set of active stakers (publicly readable from `get_stakers`). It can be repeated every block at low cost.

---

### Recommendation

Replace the single global `last_reward_block` with a **per-staker** mapping, or add an early-return (instead of a hard revert) when the block has already been processed for the given staker. The analogous fix to the PERMIT2 pattern is to silently skip (return early) rather than revert when the guard condition is already satisfied:

```cairo
// Instead of:
assert!(current_block_number > self.last_reward_block.read(), ...);

// Use per-staker tracking:
if current_block_number <= self.last_reward_block_per_staker.read(staker_address) {
    return; // already updated this block for this staker, no revert
}
```

This eliminates the cross-staker interference while preserving the one-update-per-block-per-staker invariant.

---

### Proof of Concept

1. Block N begins. The consensus mechanism (or staker B) prepares `update_rewards(staker_B, false)`.
2. Attacker observes the pending transaction and submits `update_rewards(staker_A, false)` for any other active staker with higher priority.
3. Attacker's transaction executes first:
   - `current_block_number (N) > last_reward_block (N-1)` → passes
   - `last_reward_block` written to `N`
   - Staker A's rewards updated
4. Staker B's transaction executes next:
   - `current_block_number (N) > last_reward_block (N)` → **false → revert** `REWARDS_ALREADY_UPDATED`
5. Staker B's reward update for block N is lost. The attacker repeats this every block at negligible cost. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L1449-1486)
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

```

**File:** src/staking/staking.cairo (L1558-1571)
```text
        fn calculate_block_rewards(
            ref self: ContractState,
            reward_supplier_dispatcher: IRewardSupplierDispatcher,
            curr_epoch: Epoch,
        ) -> (Amount, Amount) {
            if curr_epoch > self.last_calculated_epoch.read() {
                self.last_calculated_epoch.write(curr_epoch);
                let block_rewards = reward_supplier_dispatcher.update_current_epoch_block_rewards();
                self.block_rewards.write(block_rewards);
                block_rewards
            } else {
                self.block_rewards.read()
            }
        }
```
