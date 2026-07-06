### Title
Unrestricted `disable_rewards` Parameter Allows Any Caller to Permanently Block Consensus Reward Distribution — (File: src/staking/staking.cairo)

---

### Summary

The publicly callable `update_rewards` function accepts a caller-controlled `disable_rewards` boolean. When set to `true`, the function still writes to the global `last_reward_block` storage slot before returning early — consuming the per-block reward slot without distributing any rewards. Any non-zero address can call this every block to permanently prevent all stakers from receiving consensus-mode block rewards.

---

### Finding Description

`update_rewards` is part of the `IStakingRewardsManager` public interface with no access control beyond `general_prerequisites` (unpaused + non-zero caller). [1](#0-0) 

The critical ordering flaw: [2](#0-1) 

`last_reward_block` is written at line 1485 **before** the `disable_rewards` guard at line 1487. `last_reward_block` is a **global** (not per-staker) state variable: [3](#0-2) 

Once written, no other staker can call `update_rewards` in the same block. The block's reward slot is consumed, and the block rewards are never registered with the reward supplier via `update_unclaimed_rewards_from_staking_contract`: [4](#0-3) 

Because the reward supplier only tracks rewards that are explicitly registered, rewards for griefed blocks are permanently lost — they are never minted or credited to any staker.

The attacker does **not** need to be a staker. They only need to supply any valid `staker_address` that passes the active-staker and non-zero-balance checks: [5](#0-4) 

Valid staker addresses and their balances are fully observable on-chain.

---

### Impact Explanation

In consensus mode (post `consensus_rewards_first_epoch`), block rewards are the sole mechanism for stakers to accrue yield. An attacker calling `update_rewards(any_valid_staker, disable_rewards: true)` every block:

1. Consumes the global per-block reward slot.
2. Distributes zero rewards to any staker.
3. Permanently destroys the block rewards for each griefed block (never registered with the reward supplier).

This constitutes **permanent freezing of unclaimed yield** for all stakers and their delegators — a **High** impact under the allowed scope.

---

### Likelihood Explanation

- **No privileged role required**: any non-zero address suffices.
- **Target is public**: active staker addresses with non-zero epoch balances are observable from on-chain events (`NewStaker`, `StakeOwnBalanceChanged`).
- **Cost**: only gas per block. Starknet L2 gas costs are low enough to make sustained per-block griefing economically viable.
- **No profit required**: the attacker may be a competitor, a protocol adversary, or simply a griefing actor.

---

### Recommendation

Move `self.last_reward_block.write(current_block_number)` to **after** the `disable_rewards` guard, so that a call with `disable_rewards = true` does not consume the block's reward slot:

```cairo
// FIXED ordering:
if disable_rewards || self.is_pre_consensus() {
    return;
}
// Only update last_reward_block when rewards are actually distributed.
self.last_reward_block.write(current_block_number);
// ... rest of reward distribution
```

Additionally, audit whether `disable_rewards = true` has any legitimate external use case; if not, remove the parameter or restrict it to a privileged role.

---

### Proof of Concept

1. Consensus rewards are active (`current_epoch >= consensus_rewards_first_epoch`).
2. Attacker (any EOA, not a staker) identifies any active staker `S` with non-zero STRK balance at the current epoch (read from on-chain trace or events).
3. Each block, attacker submits: `update_rewards(S, disable_rewards: true)`.
4. Inside the call:
   - `current_block_number > last_reward_block` passes (new block).
   - `internal_staker_info(S)` succeeds (S is valid).
   - `is_staker_active(S, curr_epoch)` passes.
   - `staker_total_strk_balance.is_non_zero()` passes.
   - **`last_reward_block` is written to `current_block_number`.**
   - `disable_rewards == true` → early return, zero rewards distributed.
5. Any legitimate staker attempting `update_rewards` in the same block receives `REWARDS_ALREADY_UPDATED`.
6. Block rewards for that block are never passed to `update_unclaimed_rewards_from_staking_contract` and are permanently lost.
7. Repeated every block → all stakers are permanently frozen out of consensus rewards. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L1449-1458)
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
```

**File:** src/staking/staking.cairo (L1466-1482)
```text
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

**File:** src/staking/staking.cairo (L2350-2354)
```text
            // Update total rewards.
            reward_supplier_dispatcher
                .update_unclaimed_rewards_from_staking_contract(
                    rewards: staker_rewards + total_pools_rewards,
                );
```
