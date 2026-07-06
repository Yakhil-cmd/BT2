### Title
Unbounded Loop in `calculate_rewards` Enables Permanent Freezing of Delegator's Unclaimed Yield - (File: `src/pool/pool.cairo`)

### Summary
The `calculate_rewards` internal function in the Pool contract contains an explicitly acknowledged unbounded loop that iterates over a pool member's entire balance-change trace. Because any unprivileged delegator can grow their own `pool_member_epoch_balance` trace without bound by calling `add_to_delegation_pool` (or cycling intent/action) once per epoch, the loop can eventually exceed the Starknet transaction gas limit, permanently bricking that delegator's `claim_rewards` call and freezing all accumulated unclaimed yield.

### Finding Description
`calculate_rewards` in `src/pool/pool.cairo` iterates over every entry in the caller's `pool_member_epoch_balance` trace between the stored checkpoint and the current epoch:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch { break; }
    let to_sigma = self.find_sigma(pool_member_checkpoint, curr_epoch: until_epoch);
    ...
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

Each iteration calls `find_sigma`, which performs multiple storage reads from `cumulative_rewards_trace_vec`. [2](#0-1) 

The trace backing this loop is `pool_member_epoch_balance`, a `PoolMemberBalanceTrace` (a `Vec` of checkpoints). The `insert` function appends a **new** checkpoint whenever the pool member changes their balance in a **different epoch** from the last recorded one:

```cairo
} else {
    assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
``` [3](#0-2) 

There is no cap on the length of this `Vec`. A delegator who calls `add_to_delegation_pool` (or performs any balance-changing operation) once per epoch will append one new checkpoint per epoch, indefinitely.

### Impact Explanation
Once the trace is large enough that the loop's cumulative storage-read cost exceeds the Starknet transaction gas ceiling, every future call to `claim_rewards` for that pool member will revert with an out-of-gas error. The pool member's accumulated unclaimed yield becomes permanently inaccessible — matching the **"Permanent freezing of unclaimed yield"** impact category.

### Likelihood Explanation
The growth rate is bounded by one entry per epoch. However:
- There is no minimum-amount guard on `add_to_delegation_pool`, so a delegator can add dust amounts each epoch at negligible cost.
- Starknet epochs are short (on the order of hours to days in the pre-consensus phase), meaning thousands of entries can accumulate within months to years of normal protocol operation.
- The developers themselves flag the risk inline: *"This loop is unbounded but unlikely to exceed gas limits"* — acknowledging the hazard exists but relying on an informal assumption rather than a hard bound.
- A long-lived, active delegator who never claims rewards (letting the checkpoint lag far behind the current epoch) faces the worst-case iteration count.

### Recommendation
1. **Cap trace growth**: Enforce a maximum number of balance-change checkpoints per pool member, or consolidate/prune old checkpoints when a new one is inserted.
2. **Paginate reward claims**: Allow `claim_rewards` to accept a `max_iterations` parameter and store the updated `entry_to_claim_from` index so rewards can be claimed in multiple transactions.
3. **Incentivize frequent claiming**: Require or encourage pool members to claim rewards before making new balance changes, keeping the unclaimed window small.

### Proof of Concept
1. Delegator `D` calls `add_to_delegation_pool` with a minimal amount in epoch `E`.
2. In epoch `E+1`, `D` calls `add_to_delegation_pool` again — a new checkpoint is appended to `pool_member_epoch_balance[D]`.
3. `D` repeats step 2 every epoch for `N` epochs without ever calling `claim_rewards`.
4. After `N` epochs, `pool_member_epoch_balance[D]` has `N` checkpoints.
5. `D` calls `claim_rewards`. Internally, `calculate_rewards` is invoked with `entry_to_claim_from = 0` and `pool_member_trace_length = N`.
6. The `while` loop executes `N` iterations, each performing multiple storage reads via `find_sigma`. [4](#0-3) 

7. For sufficiently large `N`, the cumulative gas cost of the loop exceeds the Starknet transaction gas limit, the call reverts, and `D`'s unclaimed yield is permanently frozen.

### Citations

**File:** src/pool/pool.cairo (L844-877)
```text
            let pool_member_trace = self.pool_member_epoch_balance.entry(pool_member);
            // Note: `until_epoch` is the current epoch.
            let until_epoch = until_checkpoint.epoch();

            let mut rewards = 0;

            let pool_member_trace_length = pool_member_trace.length();

            let mut from_sigma = self.find_sigma(from_checkpoint, curr_epoch: until_epoch);
            let mut from_balance = from_checkpoint.balance();

            let base_value = self.staking_rewards_base_value.read();

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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L163-175)
```text
        // Update or append new checkpoint.
        let mut last = checkpoints[len - 1].read();
        let prev = last.value;
        if last.key == key {
            last.value = value;
            checkpoints[len - 1].write(last);
        } else {
            // Checkpoint keys must be non-decreasing.
            assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
            checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
        }
        (prev, value)
    }
```
