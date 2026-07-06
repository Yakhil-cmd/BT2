### Title
Unprivileged Caller Can Permanently Freeze Block Rewards by Calling `update_rewards` with `disable_rewards = true` Before the Legitimate Block Proposer - (File: src/staking/staking.cairo)

---

### Summary

`update_rewards` in `staking.cairo` writes `last_reward_block` to the current block number **before** checking the `disable_rewards` flag and returning early. Because `last_reward_block` is a global, single-slot guard that prevents duplicate reward processing per block, any unprivileged caller can invoke `update_rewards(staker_address, disable_rewards: true)` to permanently consume the per-block reward slot without distributing any rewards. The legitimate block proposer's subsequent call for the same block will revert with `REWARDS_ALREADY_UPDATED`, and the rewards for that block are irrecoverably lost.

---

### Finding Description

In `StakingRewardsManagerImpl::update_rewards` the guard variable `last_reward_block` is committed to storage at line 1485, **before** the conditional early-return at line 1487:

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // ← committed first

if disable_rewards || self.is_pre_consensus() {
    return;                                            // ← early return, no rewards distributed
}
``` [1](#0-0) 

The function's only access control is `general_prerequisites()`, which checks only that the contract is not paused and the caller is non-zero:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [2](#0-1) 

`last_reward_block` is a single global storage slot (not per-staker):

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [3](#0-2) 

The duplicate-call guard at the top of the function enforces that only one call per block can succeed:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [4](#0-3) 

Because `last_reward_block` is written before the early return, calling `update_rewards(any_staker, disable_rewards: true)` at block N:

1. Passes all validation checks.
2. Writes `last_reward_block = N`.
3. Returns immediately — `_update_rewards` is never called, so `staker_info.unclaimed_rewards_own` is never incremented and no pool rewards are forwarded.
4. Any subsequent call for block N (including the legitimate proposer's call with `disable_rewards: false`) reverts with `REWARDS_ALREADY_UPDATED`.

The actual reward distribution happens only inside `_update_rewards`:

```cairo
staker_info.unclaimed_rewards_own += staker_rewards;
// ...
let pool_rewards_list = self.update_pool_rewards(:staker_address, :pools_rewards_data);
``` [5](#0-4) 

---

### Impact Explanation

Every block for which an attacker front-runs the legitimate `update_rewards` call with `disable_rewards: true` results in:

- The staker's `unclaimed_rewards_own` not being incremented — **permanent freezing of unclaimed yield** for the staker.
- Pool rewards not being forwarded to delegation pools — **permanent freezing of unclaimed yield** for all delegators of that staker.
- Because `last_reward_block` is global, a single front-run call affects the entire protocol for that block, not just one staker.

This matches the **High** impact category: *Permanent freezing of unclaimed yield or unclaimed royalties*.

---

### Likelihood Explanation

`update_rewards` is a public, permissionless function callable by any non-zero address. No stake, role, or privileged key is required. An attacker only needs to monitor the mempool (or simply call the function at the start of each block) and submit a transaction with `disable_rewards: true` before the legitimate block proposer. On Starknet, where transaction ordering within a block is deterministic and sequencer-controlled, a griefing actor can systematically suppress rewards every block at negligible cost (only gas).

---

### Recommendation

Move the `last_reward_block` write to **after** the early-return guard, so that the block slot is only consumed when rewards are actually processed:

```cairo
// Only mark the block as processed if rewards will actually be distributed.
if disable_rewards || self.is_pre_consensus() {
    return;
}

// Update last block rewards.
self.last_reward_block.write(current_block_number);

// Get current block data and update rewards.
...
```

Alternatively, add access control to `update_rewards` so that only the designated consensus/attestation contract (or the staker's operational address) may call it.

---

### Proof of Concept

1. Staker `S` is active and has non-zero balance. Consensus rewards are active (`is_pre_consensus() == false`).
2. At block `N`, attacker `A` (any EOA) calls:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
3. The call succeeds: `last_reward_block` is set to `N`, function returns early.
4. The legitimate block proposer (or anyone) calls:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: false)
   ```
   This reverts with `REWARDS_ALREADY_UPDATED` because `current_block_number (N) > last_reward_block (N)` is false.
5. Staker `S` and all its delegators receive zero rewards for block `N`. The attacker repeats this every block to permanently suppress all consensus rewards. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
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

**File:** src/staking/staking.cairo (L2362-2365)
```text
            staker_info.unclaimed_rewards_own += staker_rewards;

            // Update pools rewards.
            let pool_rewards_list = self.update_pool_rewards(:staker_address, :pools_rewards_data);
```
