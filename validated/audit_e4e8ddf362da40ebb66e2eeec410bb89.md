### Title
Shared `last_reward_block` State Allows Any Caller to Permanently Freeze Unclaimed Yield for All Other Stakers Per Block — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract uses a single global `last_reward_block` storage variable to gate reward distribution. Because this variable is shared across all stakers and the function carries no caller access control, any unprivileged address can call `update_rewards` first in a given block — even with `disable_rewards = true` — and permanently prevent every other staker from receiving consensus rewards for that block.

---

### Finding Description

`update_rewards` is the sole reward-distribution path in the consensus-rewards phase (V3). Its guard reads:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

Immediately after the assertion, regardless of the `disable_rewards` flag, the contract writes:

```cairo
self.last_reward_block.write(current_block_number);

if disable_rewards || self.is_pre_consensus() {
    return;          // ← returns WITHOUT distributing rewards, but AFTER updating the lock
}
``` [1](#0-0) 

`last_reward_block` is a single `BlockNumber` field in the contract's `Storage` struct — it is not keyed per staker:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [2](#0-1) 

The only prerequisite enforced before the lock is written is `general_prerequisites()`, which only checks that the contract is unpaused and the caller is non-zero — no role, no staker-identity check:

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
``` [3](#0-2) 

Because `last_reward_block` is global and the function is fully public, the first call to `update_rewards` in any block — for **any** staker, with **any** `disable_rewards` value — consumes the per-block slot and causes every subsequent call in the same block to revert with `REWARDS_ALREADY_UPDATED`. This is the direct analog of the external report: shared state keyed only by a monotonically-advancing counter (block number) that does not differentiate between the many independent actors (stakers) that legitimately need to interact with it.

---

### Impact Explanation

In the consensus-rewards phase, `update_rewards` is the mechanism by which a staker's `unclaimed_rewards_own` is incremented and pool rewards are forwarded. If the call reverts, `reward_supplier_dispatcher.update_unclaimed_rewards_from_staking_contract` is never invoked, `staker_info.unclaimed_rewards_own` is never incremented, and pool rewards are never transferred. The yield for that block is permanently lost — it is never re-queued or retried. This constitutes **permanent freezing of unclaimed yield** for every staker whose `update_rewards` call is blocked.

---

### Likelihood Explanation

The attack requires no privilege, no stake, and no special timing beyond being the first transaction in a block. An attacker can:

1. Call `update_rewards(staker_address: <any_valid_staker>, disable_rewards: true)` as the first transaction of every block.
2. `last_reward_block` is set to the current block number; no rewards are distributed.
3. Every legitimate `update_rewards` call in that block reverts.

The cost is one cheap transaction per block. The attack is sustainable indefinitely and requires no profit motive — it is pure griefing with direct, measurable damage to all stakers.

---

### Recommendation

1. **Per-staker lock:** Replace the global `last_reward_block: BlockNumber` with a per-staker map `last_reward_block: Map<ContractAddress, BlockNumber>` so that one staker's call does not block another's.
2. **Access control:** Restrict `update_rewards` to a trusted caller (e.g., the consensus contract or the staker themselves) so that arbitrary addresses cannot consume the per-block slot.
3. **Separate the lock from the early-return path:** If `disable_rewards = true` is a valid no-op path, it should not update `last_reward_block` at all, or the lock should be moved to after the early-return check.

---

### Proof of Concept

**Setup:** Consensus rewards are active (`is_pre_consensus()` returns `false`). Staker B is the legitimately selected staker for block N.

**Attack:**

1. Attacker (any address) submits `update_rewards(staker_address: <any_active_staker>, disable_rewards: true)` as the first transaction in block N.
2. The function passes `general_prerequisites()`, passes the `last_reward_block` assertion (since `N > last_reward_block`), and writes `last_reward_block = N`. It then hits `if disable_rewards { return; }` — no rewards are distributed.
3. Staker B (or the consensus mechanism on B's behalf) submits `update_rewards(staker_address: B, disable_rewards: false)` in the same block N.
4. The assertion `current_block_number > self.last_reward_block.read()` evaluates as `N > N` → **false** → reverts with `REWARDS_ALREADY_UPDATED`.
5. Staker B's `unclaimed_rewards_own` is never incremented; pool rewards are never forwarded. The yield for block N is permanently lost.

Repeating this every block permanently freezes all consensus-phase yield across the entire protocol.

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1452-1490)
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
