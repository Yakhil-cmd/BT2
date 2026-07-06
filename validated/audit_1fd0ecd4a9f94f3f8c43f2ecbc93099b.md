### Title
Unrestricted `update_rewards` with `disable_rewards: true` Allows Any Caller to Permanently Block Consensus Reward Distribution — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract is publicly callable by any address and accepts a caller-controlled `disable_rewards` boolean. When called with `disable_rewards: true`, the function writes the global `last_reward_block` to the current block number and returns early without distributing any rewards. Because only one `update_rewards` call can succeed per block (enforced by the `REWARDS_ALREADY_UPDATED` guard), an attacker who front-runs every block with `disable_rewards: true` permanently prevents all stakers from receiving consensus rewards.

---

### Finding Description

In `src/staking/staking.cairo`, `StakingRewardsManagerImpl::update_rewards` has no role-based access control. The function:

1. Checks `current_block_number > self.last_reward_block.read()` — passes on the first call per block.
2. **Unconditionally writes** `self.last_reward_block.write(current_block_number)` — before inspecting `disable_rewards`.
3. Then checks `if disable_rewards || self.is_pre_consensus() { return; }` — exits without distributing rewards. [1](#0-0) 

`last_reward_block` is a single global storage slot (not per-staker). Any call that passes the block-number guard consumes the slot for the entire protocol for that block. [2](#0-1) 

The `IStakingRewardsManager` interface imposes no caller restriction: [3](#0-2) 

The only prerequisite is `general_prerequisites()`, which checks the pause flag — not the caller identity.

---

### Impact Explanation

An attacker calls `update_rewards(any_active_staker, disable_rewards: true)` at the start of every block. Each call:
- Passes all guards (contract live, block advanced, staker active, non-zero balance).
- Writes `last_reward_block = current_block`.
- Returns without distributing rewards.

Every subsequent legitimate call in that block reverts with `REWARDS_ALREADY_UPDATED`. Repeated every block, this constitutes **permanent freezing of unclaimed consensus-phase yield** for every staker in the protocol.

This matches the allowed impact: *"High: Permanent freezing of unclaimed yield."*

---

### Likelihood Explanation

- **No privilege required**: any EOA or contract can call `update_rewards`.
- **Active staker address**: trivially obtained from on-chain events (`NewStaker`).
- **Cost**: Starknet transaction fees are low; automating one call per block is economically viable.
- **No profit needed**: a competitor, protocol adversary, or griefing bot suffices.

---

### Recommendation

Move `last_reward_block.write(current_block_number)` to **after** the `disable_rewards` guard, so a `disable_rewards: true` call does not consume the block's reward slot:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
self.last_reward_block.write(current_block_number); // moved here
// ... distribute rewards
```

Alternatively, add an access-control check (e.g., `only_staker_or_operator`) to restrict who may call `update_rewards`.

---

### Proof of Concept

1. Attacker monitors Starknet for new blocks.
2. At each new block, attacker submits: `update_rewards(known_active_staker, disable_rewards: true)`.
3. The call passes: contract unpaused ✓, `block_number > last_reward_block` ✓, staker active ✓, balance non-zero ✓.
4. `last_reward_block` is set to the current block number.
5. Function returns early — zero rewards distributed.
6. Any legitimate `update_rewards(staker, disable_rewards: false)` call in the same block reverts with `REWARDS_ALREADY_UPDATED`. [4](#0-3) 

7. Repeated every block → all stakers permanently frozen out of consensus rewards.

**Analog mapping**: Just as calling `fcnCheckBarriers` incremented `observationsDone` and caused `checkTradeExpiry` to overflow-revert (freezing the vault), calling `update_rewards` with `disable_rewards: true` sets `last_reward_block` and causes every legitimate reward-distribution call to revert with `REWARDS_ALREADY_UPDATED`, freezing all unclaimed yield.

### Citations

**File:** src/staking/staking.cairo (L1452-1489)
```text
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
