### Title
Unbounded Loop Over Pool Member Balance Trace in Reward Calculation Causes Permanent Freezing of Unclaimed Yield - (File: src/pool/pool.cairo)

### Summary
The internal function `compute_rewards_and_update_entry_to_claim_from` in `pool.cairo` contains an unbounded `while` loop that iterates over a pool member's entire balance trace since their last claim. A pool member who changes their delegation balance across many epochs accumulates an ever-growing trace. When the trace grows large enough, every call to `claim_rewards` will revert with out-of-gas, permanently freezing the pool member's unclaimed yield with no recovery path.

### Finding Description
In `src/pool/pool.cairo`, the function `compute_rewards_and_update_entry_to_claim_from` (lines 840–888) iterates over the `pool_member_epoch_balance` trace using an unbounded `while` loop:

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
    ...
    entry_to_claim_from += 1;
}
```

The code itself acknowledges the loop is unbounded (line 858 comment). Each iteration calls `find_sigma`, which performs additional storage reads against `cumulative_rewards_trace`. The `pool_member_epoch_balance` trace grows by one entry each time a pool member changes their delegation balance in a new epoch (via `add_to_delegation_pool`, `exit_delegation_pool_intent`, or re-entry). There is no cap on the number of entries. The `entry_to_claim_from` cursor is only advanced after a successful claim; if the pool member delays claiming while repeatedly changing their balance, the pending range grows without bound.

### Impact Explanation
Once the trace is large enough that a single `claim_rewards` call exhausts the Starknet block gas limit, the pool member's rewards are permanently frozen. There is no partial-claim or pagination mechanism — the entire pending range must be processed in one transaction. The pool member cannot recover their accrued yield.

**Impact: High — Permanent freezing of unclaimed yield.**

### Likelihood Explanation
A pool member who is active over many epochs and regularly adjusts their delegation (e.g., topping up or partially exiting each epoch) will naturally accumulate one trace entry per epoch. After hundreds or thousands of epochs without a claim, the loop becomes prohibitively expensive. This can also be triggered deliberately: a pool member calls `add_to_delegation_pool` with a minimal amount each epoch to inflate their trace, then stops claiming. No privileged access is required — any pool member can reach this state through normal or adversarial usage.

### Recommendation
1. **Add a maximum trace length cap**: Enforce a hard limit on the number of entries in `pool_member_epoch_balance` per pool member, reverting any balance-change call that would exceed it.
2. **Implement paginated claiming**: Allow `claim_rewards` to accept a `max_entries` parameter and process only that many trace entries per call, storing the updated `entry_to_claim_from` cursor so subsequent calls resume where the previous one stopped.
3. **Consolidate trace entries**: When a pool member claims rewards, compact their trace to a single checkpoint representing the current state, preventing unbounded growth.

### Proof of Concept
1. Pool member `A` calls `add_to_delegation_pool` with a small amount in epoch `E`.
2. In each subsequent epoch `E+1, E+2, ..., E+N`, pool member `A` calls `add_to_delegation_pool` again (even with 1 unit), adding a new entry to `pool_member_epoch_balance` each time.
3. Pool member `A` never calls `claim_rewards`, so `entry_to_claim_from` remains at 0.
4. After `N` epochs, pool member `A` calls `claim_rewards`. The loop at line 859 must iterate `N` times, each iteration calling `find_sigma` (storage reads into `cumulative_rewards_trace`).
5. For sufficiently large `N`, the transaction exceeds the gas limit and reverts.
6. Every subsequent `claim_rewards` call also reverts — the yield is permanently frozen. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/pool/pool.cairo (L840-843)
```text
            from_checkpoint: PoolMemberCheckpoint,
            until_checkpoint: PoolMemberCheckpoint,
            mut entry_to_claim_from: VecIndex,
        ) -> (Amount, VecIndex) {
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

**File:** src/pool/pool.cairo (L897-933)
```text
        fn find_sigma(
            self: @ContractState, pool_member_checkpoint: PoolMemberCheckpoint, curr_epoch: Epoch,
        ) -> Amount {
            let pool_member_checkpoint_epoch = pool_member_checkpoint.epoch();
            assert!(
                pool_member_checkpoint_epoch <= curr_epoch,
                "{}",
                InternalError::INVALID_EPOCH_IN_TRACE,
            );
            let cumulative_rewards_trace_vec = self.cumulative_rewards_trace;
            let cumulative_rewards_trace_idx = pool_member_checkpoint
                .cumulative_rewards_trace_idx();

            // **Reminder**:
            // Let `len` be the length of `cumulative_rewards_trace_vec` at the time the checkpoint
            // is written.
            // In old version: `cumulative_rewards_trace_idx` = `len`.
            // In this version: `cumulative_rewards_trace_idx` = `len + 1`.
            // For current checkpoint in both versions: `cumulative_rewards_trace_idx` = `len - 1`.
            // **Invariant**:
            // 1. `cumulative_rewards_trace_vec.length() >= 1`.
            // 2. `cumulative_rewards_trace_vec.length()` is only increased, never decreased.
            if let Some(sigma) =
                find_sigma_edge_cases(
                    :cumulative_rewards_trace_vec,
                    :cumulative_rewards_trace_idx,
                    target_epoch: pool_member_checkpoint_epoch,
                ) {
                return sigma;
            }

            find_sigma_standard_case(
                :cumulative_rewards_trace_vec,
                :cumulative_rewards_trace_idx,
                target_epoch: pool_member_checkpoint_epoch,
            )
        }
```
