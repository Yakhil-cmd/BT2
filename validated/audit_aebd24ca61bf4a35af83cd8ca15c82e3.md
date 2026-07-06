### Title
Unpermissioned `update_rewards` Caller Can Permanently Freeze All Staker Block Rewards by Consuming `last_reward_block` Without Distributing Rewards - (File: src/staking/staking.cairo)

### Summary
`IStakingRewardsManager::update_rewards` is callable by any non-zero address and accepts a caller-controlled `disable_rewards: bool` parameter. The function unconditionally writes `last_reward_block = current_block_number` **before** checking `disable_rewards`. An attacker who calls `update_rewards(any_active_staker, true)` once per block permanently consumes the per-block reward slot without distributing any rewards, freezing all staker and delegator yield for every block they front-run.

### Finding Description

`update_rewards` in `IStakingRewardsManager` is a public, permissionless function:

```
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
)
```

The only access control is `general_prerequisites()`, which checks the contract is not paused and the caller is non-zero. No role check exists.

Inside the function the execution order is:

1. Assert `current_block_number > self.last_reward_block.read()` — ensures only one reward update per block.
2. Assert staker exists and is active.
3. **`self.last_reward_block.write(current_block_number);`** — the slot is consumed here, unconditionally.
4. `if disable_rewards || self.is_pre_consensus() { return; }` — early return without distributing rewards. [1](#0-0) 

Because step 3 happens before step 4, calling with `disable_rewards = true` marks the block as "already rewarded" while distributing nothing. Any subsequent legitimate call in the same block fails at step 1 with `REWARDS_ALREADY_UPDATED`. [2](#0-1) 

The `last_reward_block` field is a single global value shared across all stakers: [3](#0-2) 

The interface confirms the function is public with no role restriction: [4](#0-3) 

### Impact Explanation

Every block in which the attacker front-runs legitimate callers, **zero** STRK block rewards are distributed to any staker or delegation pool. The rewards for that block are permanently lost — the `reward_supplier` is never queried, `unclaimed_rewards_own` is never incremented, and pool contracts never receive their share. Repeated across every block, this permanently freezes all unclaimed yield for the entire protocol.

This matches the allowed impact: **High — Permanent freezing of unclaimed yield**.

### Likelihood Explanation

- The function is permissionless; any EOA or contract can call it.
- The attacker needs only to submit a transaction before any legitimate `update_rewards` call in each block — a straightforward mempool front-run or a bot that monitors the chain.
- The cost is only gas per block; no capital is required.
- The attacker gains nothing financially, making this a pure griefing attack, but the damage to stakers and delegators is total and ongoing.

### Recommendation

Move `self.last_reward_block.write(current_block_number)` to **after** the `disable_rewards` / `is_pre_consensus()` guard, so the block slot is only consumed when rewards are actually distributed:

```cairo
// Update last block rewards ONLY when rewards will actually be distributed.
if disable_rewards || self.is_pre_consensus() {
    return;
}
self.last_reward_block.write(current_block_number);
// ... proceed with reward calculation
```

Alternatively, restrict `update_rewards` to a trusted caller role (e.g., the attestation contract or a dedicated rewards-manager role) so that arbitrary addresses cannot invoke it.

### Proof of Concept

1. Consensus rewards are active (`consensus_rewards_first_epoch` has been set and the current epoch has passed it).
2. Attacker deploys a bot that, at the start of every block, calls:
   ```
   staking.update_rewards(any_active_staker_address, disable_rewards=true)
   ```
3. The call passes all checks: contract is unpaused, caller is non-zero, `current_block_number > last_reward_block`, staker is active and has non-zero balance.
4. `last_reward_block` is written to `current_block_number` at line 1485.
5. The function returns early at line 1487–1489 without calling `_update_rewards`.
6. Any legitimate staker or protocol bot that calls `update_rewards` later in the same block hits the `REWARDS_ALREADY_UPDATED` assertion at line 1455–1458 and reverts.
7. Repeated every block: all stakers accumulate zero `unclaimed_rewards_own` and all delegation pools receive zero STRK rewards indefinitely. [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1453-1489)
```text
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
