### Title
Unbounded loop in `calculate_rewards` over pool member balance trace can permanently freeze unclaimed yield — (`src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` function in `pool.cairo` contains an unbounded `while` loop that iterates over every entry in a pool member's `pool_member_epoch_balance` trace. The code itself acknowledges this risk. A pool member who makes many balance changes across many epochs without claiming rewards will accumulate an arbitrarily large trace. When they eventually call `claim_rewards`, the loop must process all accumulated entries in a single transaction, which can exceed Starknet's gas limit and permanently freeze their unclaimed yield.

---

### Finding Description

In `pool.cairo`, the internal `calculate_rewards` function iterates over the pool member's balance-change trace:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch {
        break;
    }
    let to_sigma = self.find_sigma(pool_member_checkpoint, curr_epoch: until_epoch);
    rewards += compute_rewards_rounded_down(...);
    from_sigma = to_sigma;
    from_balance = pool_member_checkpoint.balance();
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

Every call to `enter_delegation_pool`, `add_to_delegation_pool`, or a partial `exit_delegation_pool_intent` in a new epoch appends one entry to the pool member's `pool_member_epoch_balance` trace. The `entry_to_claim_from` index is stored inside the pool member's `PoolMemberCheckpoint` and only advances when rewards are successfully claimed. [2](#0-1) 

If a pool member makes N balance changes across N distinct epochs without ever claiming rewards, the trace accumulates N entries. The next `claim_rewards` call must iterate over all N entries in a single transaction. Each iteration performs at least one storage read via `find_sigma`, making the per-iteration cost non-trivial. For large N, the transaction will exceed Starknet's gas limit and revert. Because the checkpoint is only updated on a successful claim, every subsequent attempt will also OOG — permanently locking the member's accumulated rewards. [3](#0-2) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Once the `pool_member_epoch_balance` trace grows beyond the gas-limit threshold, no single transaction can ever complete `calculate_rewards` for that member. The checkpoint never advances, so every future `claim_rewards` call starts from the same oversized trace and OOGs again. The pool member's accumulated STRK rewards are permanently inaccessible.

---

### Likelihood Explanation

**Medium.**

The scenario requires a pool member to make frequent balance changes (partial exits, top-ups) across many epochs without claiming. Epochs in Starknet staking are measured in blocks/time, so an active participant over months or years can realistically accumulate hundreds to thousands of trace entries. The developers themselves flagged the loop as unbounded, indicating awareness of the risk. No privileged access is required — any pool member can reach this state through normal protocol interactions.

---

### Recommendation

1. **Paginate reward claiming**: Allow `claim_rewards` to accept a `max_entries` parameter and process only that many trace entries per call, updating the checkpoint after each partial claim.
2. **Checkpoint on every balance change**: Force a reward settlement (or at least a checkpoint update) whenever a pool member modifies their balance, keeping the unclaimed window bounded to at most one entry per call.
3. **Cap trace growth**: Enforce a maximum number of unprocessed balance-change entries before allowing further balance modifications, requiring the member to claim first.

---

### Proof of Concept

1. Pool member calls `enter_delegation_pool` in epoch E₀ — trace length = 1.
2. Pool member calls `add_to_delegation_pool` in epoch E₁ — trace length = 2.
3. Pool member calls `exit_delegation_pool_intent` (partial) in epoch E₂ — trace length = 3.
4. Steps 2–3 are repeated across hundreds of epochs without ever calling `claim_rewards`.
5. After N epochs, `pool_member_epoch_balance` trace length = N.
6. Pool member calls `claim_rewards`. The `calculate_rewards` loop must iterate N times, each time calling `find_sigma` (storage reads). For N ≈ a few hundred to a few thousand (depending on per-iteration gas cost), the transaction OOGs.
7. The checkpoint is never updated. Every subsequent `claim_rewards` attempt starts from the same position and OOGs identically.
8. The pool member's unclaimed STRK yield is permanently frozen. [4](#0-3)

### Citations

**File:** src/pool/pool.cairo (L808-820)
```text
        /// Returns the checkpoint for the current epoch.
        ///
        /// This function is called when claiming rewards.
        fn get_current_checkpoint(
            self: @ContractState, pool_member: ContractAddress,
        ) -> PoolMemberCheckpoint {
            let current_epoch = self.get_current_epoch();
            PoolMemberCheckpointTrait::new(
                epoch: current_epoch,
                balance: self.get_balance_at_current_epoch(:pool_member, :current_epoch),
                cumulative_rewards_trace_idx: self.cumulative_rewards_trace_length() - 1,
            )
        }
```

**File:** src/pool/pool.cairo (L837-845)
```text
        fn calculate_rewards(
            self: @ContractState,
            pool_member: ContractAddress,
            from_checkpoint: PoolMemberCheckpoint,
            until_checkpoint: PoolMemberCheckpoint,
            mut entry_to_claim_from: VecIndex,
        ) -> (Amount, VecIndex) {
            let pool_member_trace = self.pool_member_epoch_balance.entry(pool_member);
            // Note: `until_epoch` is the current epoch.
```

**File:** src/pool/pool.cairo (L857-877)
```text
            // **Note**: The loop iterates over the balance changes in the pool member's balance
            // trace. This loop is unbounded but unlikely to exceed gas limits.
            while entry_to_claim_from < pool_member_trace_length {
                let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
                // If the balance change is after `until_epoch` (and therefore does not affect
                // the current reward computation), exit the loop.
                if pool_member_checkpoint.epoch() >= until_epoch {
                    break;
                }

                // Compute rewards from (inclusive) the previous balance change (or from
                // `from_checkpoint`) to (exclusive) the current entry.
                let to_sigma = self.find_sigma(pool_member_checkpoint, curr_epoch: until_epoch);
                rewards +=
                    compute_rewards_rounded_down(
                        amount: from_balance, interest: to_sigma - from_sigma, :base_value,
                    );
                from_sigma = to_sigma;
                from_balance = pool_member_checkpoint.balance();
                entry_to_claim_from += 1;
            }
```
