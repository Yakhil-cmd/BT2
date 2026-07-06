### Title
Unprivileged Caller Can Permanently Deny All Stakers' Block Rewards via `update_rewards` with `disable_rewards: true` — (File: `src/staking/staking.cairo`)

---

### Summary

`StakingRewardsManagerImpl::update_rewards` in `src/staking/staking.cairo` writes the global `last_reward_block` state variable **before** checking whether rewards should actually be distributed. Because the function has no access control beyond a non-zero caller check, any unprivileged address can call it with `disable_rewards: true`, consuming the per-block reward slot for the entire protocol without distributing a single token. This is a direct analog of the external report's pattern: a critical state variable is updated (marking the block as "processed") while the full intended state transition (reward distribution) is skipped.

---

### Finding Description

In `StakingRewardsManagerImpl::update_rewards` the execution order is:

```
1. general_prerequisites()          // only checks: not paused, caller != zero
2. assert current_block > last_reward_block
3. assert staker is active with non-zero balance
4. last_reward_block.write(current_block_number)   ← state committed here
5. if disable_rewards || is_pre_consensus() { return; }  ← early exit, no rewards
6. ... actual reward calculation and distribution ...
``` [1](#0-0) 

`last_reward_block` is a **global** (not per-staker) storage variable: [2](#0-1) 

The guard that prevents double-processing a block is:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [3](#0-2) 

Once `last_reward_block` is written, **no other call** to `update_rewards` can succeed for that block number. Because the write happens unconditionally before the `disable_rewards` branch, an attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` once per block permanently consumes the reward slot for the entire protocol without any rewards being distributed.

The only access control is `general_prerequisites()`: [4](#0-3) 

which only asserts the contract is unpaused and the caller is non-zero — no role check, no allowlist.

---

### Impact Explanation

`last_reward_block` is global. A single call with `disable_rewards: true` blocks **all** stakers from receiving consensus-era block rewards for that block. The rewards for each attacked block are permanently lost — there is no mechanism to retroactively distribute rewards for a block whose `last_reward_block` slot has already been consumed. Sustained over multiple blocks, this constitutes permanent freezing of unclaimed yield for the entire staker set.

**Impact: High — Permanent freezing of unclaimed yield.**

---

### Likelihood Explanation

- The function is publicly callable by any non-zero address with no role restriction.
- The attacker only needs to submit one transaction per block (or per epoch, depending on desired damage).
- Gas cost is the sole barrier; no capital, no privileged key, no external dependency is required.
- The attack is reachable from the moment `consensus_rewards_first_epoch` is set and the protocol enters the consensus rewards era.

---

### Recommendation

Move `last_reward_block.write(current_block_number)` to **after** the `disable_rewards` / `is_pre_consensus()` guard, so the slot is only consumed when rewards are actually distributed:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
// Only mark the block as processed when rewards are actually distributed.
self.last_reward_block.write(current_block_number);
// ... reward calculation ...
```

Alternatively, restrict who may pass `disable_rewards: true` (e.g., only the attestation contract or a governance role), or remove the parameter entirely and handle the disable-rewards logic through a separate privileged entry point.

---

### Proof of Concept

1. Protocol enters consensus rewards era (`consensus_rewards_first_epoch` is set and passed).
2. Attacker (any EOA) monitors the chain for new blocks.
3. At block `N`, attacker calls:
   ```
   staking.update_rewards(any_active_staker_address, disable_rewards: true)
   ```
4. `last_reward_block` is written to `N`; no rewards are distributed.
5. The legitimate sequencer/attestation system attempts to call `update_rewards` for block `N` — it reverts with `REWARDS_ALREADY_UPDATED`.
6. All stakers permanently lose their block `N` rewards.
7. Attacker repeats for every subsequent block, continuously freezing all staker yield at the cost of one transaction per block.

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1489)
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
```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
