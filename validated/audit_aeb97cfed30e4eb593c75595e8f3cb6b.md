### Title
Unprivileged Caller Can Permanently Freeze All Staker Rewards via `update_rewards(disable_rewards: true)` — (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract accepts a caller-controlled `disable_rewards: bool` parameter with no access control. Any unprivileged address can call `update_rewards(any_staker, disable_rewards: true)`, which writes the current block number to the global `last_reward_block` storage slot **before** the `disable_rewards` guard is evaluated. Because `last_reward_block` is shared across all stakers, this single call permanently prevents every staker from receiving rewards for that block. An attacker repeating this every block permanently freezes all unclaimed yield across the protocol.

---

### Finding Description

`update_rewards` is exposed as a public function under `IStakingRewardsManager` with no role-based access control. Its only gate is `general_prerequisites()`, which checks only that the contract is unpaused and the caller is non-zero. [1](#0-0) 

Inside the function, `last_reward_block` is written to storage **unconditionally**, before the `disable_rewards` branch: [2](#0-1) 

The `disable_rewards` check that skips reward distribution comes **after** the storage write: [3](#0-2) 

`last_reward_block` is a single global slot, not per-staker: [4](#0-3) 

The guard at the top of the function enforces that only one call per block is accepted: [5](#0-4) 

Consequence: once an attacker calls `update_rewards(any_valid_staker, true)` in block N, `last_reward_block == N`. Every subsequent call in block N reverts with `REWARDS_ALREADY_UPDATED`. No staker can receive block rewards for block N. The attacker repeats this in block N+1, N+2, … permanently suppressing all reward distribution.

`general_prerequisites` provides no protection: [6](#0-5) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

All stakers and delegators are denied block rewards indefinitely. Because `last_reward_block` is global, a single attacker call per block is sufficient to zero out rewards for the entire protocol. Delegators' `cumulative_rewards_trace` in the pool contract is never updated, and stakers' `unclaimed_rewards_own` never increases. Rewards are not merely delayed; they are permanently lost for every suppressed block. [7](#0-6) 

---

### Likelihood Explanation

**High.** The attack requires no capital, no privileged key, and no special setup. Any EOA can call `update_rewards` with a valid (active, non-zero-balance) staker address and `disable_rewards: true`. The attacker only needs to submit one transaction per block, which is trivially automatable. There is no economic cost beyond gas fees, and the attacker gains a griefing advantage (e.g., a competing validator suppressing rivals' rewards).

---

### Recommendation

1. **Restrict `disable_rewards = true` to authorized callers only.** Add a check that `disable_rewards` can only be `true` when the caller is the attestation contract (or another trusted role). Unprivileged callers should only be permitted to call with `disable_rewards: false`.
2. **Separate the `last_reward_block` write from the reward-distribution path.** Only commit `last_reward_block` when rewards are actually distributed, or gate the write behind the same authorization check.
3. Alternatively, make `disable_rewards` an internal parameter not exposed in the public ABI, and expose two separate public entry points: one for normal reward updates (open) and one for penalized/disabled updates (restricted to the attestation contract).

---

### Proof of Concept

```
// Attacker script (pseudocode, runs every block)
loop every block B:
    staking.update_rewards(
        staker_address = any_active_staker,  // publicly readable from events
        disable_rewards = true
    )
    // last_reward_block is now B
    // No staker receives rewards for block B
    // Any legitimate update_rewards call in block B reverts with REWARDS_ALREADY_UPDATED
```

Concrete call path:
1. Attacker calls `Staking::update_rewards(staker_address, disable_rewards=true)` at block N.
2. `general_prerequisites()` passes (contract unpaused, caller non-zero). [8](#0-7) 
3. `current_block_number > last_reward_block` passes (first call this block). [5](#0-4) 
4. Staker validity checks pass (attacker picks any active staker with non-zero balance). [9](#0-8) 
5. `last_reward_block.write(current_block_number)` executes — block N is now "consumed". [10](#0-9) 
6. `disable_rewards == true` → function returns early, zero rewards distributed. [3](#0-2) 
7. All subsequent `update_rewards` calls in block N revert at step 3.
8. Attacker repeats at block N+1, N+2, … — all staker and delegator yield is permanently frozen.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1457)
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

**File:** src/staking/staking.cairo (L1484-1490)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
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

**File:** src/staking/staking.cairo (L2348-2376)
```text
            // Update reward supplier.
            let staker_rewards = staker_own_rewards + commission_rewards;
            // Update total rewards.
            reward_supplier_dispatcher
                .update_unclaimed_rewards_from_staking_contract(
                    rewards: staker_rewards + total_pools_rewards,
                );
            // Claim pools rewards.
            claim_from_reward_supplier(
                :reward_supplier_dispatcher,
                amount: total_pools_rewards,
                token_dispatcher: strk_token_dispatcher(),
            );
            // Update staker rewards.
            staker_info.unclaimed_rewards_own += staker_rewards;

            // Update pools rewards.
            let pool_rewards_list = self.update_pool_rewards(:staker_address, :pools_rewards_data);
            // Emit event.
            self
                .emit(
                    Events::StakerRewardsUpdated {
                        staker_address, staker_rewards, pool_rewards: pool_rewards_list.span(),
                    },
                );

            // Write staker rewards to storage.
            self.write_staker_info(:staker_address, :staker_info);
        }
```
