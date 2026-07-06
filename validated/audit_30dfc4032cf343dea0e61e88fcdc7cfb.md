### Title
Caller-Controlled `disable_rewards` Flag Allows Any Address to Permanently Suppress Per-Block Reward Distribution - (File: `src/staking/staking.cairo`)

---

### Summary

`IStakingRewardsManager::update_rewards` is a public, permissionless function that accepts a caller-supplied `disable_rewards: bool` flag. The function unconditionally writes `last_reward_block` to the current block number **before** checking that flag. Any unprivileged caller can invoke `update_rewards(staker_address, disable_rewards: true)` to consume the one-per-block reward slot without distributing any rewards, permanently destroying the block's yield for all stakers and delegators.

---

### Finding Description

`update_rewards` is declared in the public `IStakingRewardsManager` interface: [1](#0-0) 

The implementation in `staking.cairo` first checks that the current block has not yet been processed, then **immediately commits** `last_reward_block` before branching on `disable_rewards`: [2](#0-1) 

The only access control applied is `general_prerequisites()`, which only asserts the contract is not paused and the caller is non-zero: [3](#0-2) 

Because `last_reward_block` is written at line 1485 and the early-return branch is at line 1487, any caller who passes `disable_rewards: true` will:

1. Pass the `current_block_number > last_reward_block` guard.
2. Overwrite `last_reward_block` with the current block.
3. Return immediately — no rewards are calculated or distributed.

Every subsequent call to `update_rewards` for that block will revert with `REWARDS_ALREADY_UPDATED`. The block's rewards are permanently lost.

The `_update_rewards` path that actually distributes yield is only reached when `disable_rewards` is `false` **and** `is_pre_consensus()` is `false`: [4](#0-3) 

---

### Impact Explanation

An attacker who front-runs the legitimate `update_rewards` call every block with `disable_rewards: true` permanently prevents all consensus-phase block rewards from being distributed to stakers and their delegation pools. Because `last_reward_block` is a single global slot, one griefing transaction per block is sufficient to zero out all yield for all participants indefinitely. This constitutes **permanent freezing of unclaimed yield** for every staker and delegator in the protocol.

---

### Likelihood Explanation

The function is fully permissionless — no stake, no role, no prior interaction is required. The attacker only needs to submit a transaction each block with `disable_rewards: true` for any valid `staker_address`. On Starknet, transaction costs are low, making sustained griefing economically viable. The attack is also invisible to victims until they notice rewards have stopped accumulating.

---

### Recommendation

Move the `last_reward_block` write to **after** the `disable_rewards` guard, so the block slot is only consumed when rewards are actually distributed:

```cairo
// Check guard first
assert!(current_block_number > self.last_reward_block.read(), ...);

// Validate staker
...

if disable_rewards || self.is_pre_consensus() {
    return; // do NOT write last_reward_block
}

// Only consume the slot when rewards are actually distributed
self.last_reward_block.write(current_block_number);

// proceed with reward calculation
```

Alternatively, restrict `update_rewards` to be callable only by the attestation contract or a trusted sequencer role, removing the public attack surface entirely.

---

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. At block `N`, the legitimate sequencer/staker prepares to call `update_rewards(staker_A, false)`.
3. Attacker front-runs with `update_rewards(staker_A, true)`.
   - Guard passes: `N > last_reward_block`.
   - `last_reward_block` is written to `N`.
   - Function returns early; no rewards distributed.
4. Legitimate call arrives: `assert!(N > N)` fails → `REWARDS_ALREADY_UPDATED`.
5. Block `N`'s rewards are permanently lost for all stakers and delegators.
6. Attacker repeats at block `N+1`, `N+2`, … — all yield is frozen indefinitely. [5](#0-4)

### Citations

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
