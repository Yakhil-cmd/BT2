### Title
Unbounded Loop in `calculate_rewards` Can Permanently Freeze Delegator's Unclaimed Yield - (File: `src/pool/pool.cairo`)

### Summary
The `calculate_rewards` internal function in the Pool contract contains an explicitly unbounded loop that iterates over a pool member's entire balance-change trace. A delegator who accumulates many balance-change checkpoints across epochs without claiming rewards will eventually be unable to claim, permanently freezing their unclaimed yield.

### Finding Description

In `src/pool/pool.cairo`, the `calculate_rewards` function contains a loop that iterates over every entry in the pool member's `pool_member_epoch_balance` trace from `entry_to_claim_from` up to the current trace length: [1](#0-0) 

The developers themselves acknowledge this is unbounded:

> **Note**: The loop iterates over the balance changes in the pool member's balance trace. This loop is unbounded but unlikely to exceed gas limits.

The trace is stored as a `Vec<PoolMemberBalanceCheckpoint>` and grows by appending a new entry each time a pool member's balance changes in a **new epoch** (i.e., `last.key < key`): [2](#0-1) 

This means every epoch in which a delegator calls `delegate`, `exit_intent`, or any other balance-modifying operation adds one new checkpoint to their personal trace. A delegator who:
1. Repeatedly changes their delegated balance across many epochs, **and**
2. Defers calling `claim_rewards` for a long period

will accumulate a large trace. When `claim_rewards` is eventually called, the loop must iterate over all accumulated unclaimed entries in a single transaction. There is no pagination or partial-claim mechanism to split this work across multiple calls.

### Impact Explanation

Once the trace is large enough that a single `claim_rewards` call exhausts the transaction gas limit, the delegator's accumulated rewards become permanently unclaimable. This constitutes **permanent freezing of unclaimed yield** for the affected pool member. The frozen funds remain locked in the pool contract with no recovery path, since the only way to retrieve them is through `claim_rewards`, which itself is the failing call.

### Likelihood Explanation

The trace grows at most one entry per epoch. The rate of accumulation depends on epoch duration and how frequently the delegator changes their balance. A long-lived, active delegator who never claims rewards (e.g., intending to claim a large lump sum after years) is the realistic victim. While this requires sustained inaction over many epochs, the protocol is designed for long-term staking, making this scenario plausible. The developers' own comment acknowledges the loop is unbounded, confirming the root cause is present.

### Recommendation

Introduce a paginated reward-claiming mechanism: store the `entry_to_claim_from` index in the pool member's on-chain state so that `claim_rewards` can be called multiple times, each time processing a bounded number of trace entries and resuming from where it left off. Alternatively, cap the number of entries processed per call and emit an event indicating partial completion.

### Proof of Concept

1. Delegator calls `delegate` in epoch 1 → trace length = 1.
2. Delegator calls `exit_intent` (partial) in epoch 2 → trace length = 2.
3. Delegator calls `delegate` again in epoch 3 → trace length = 3.
4. Repeat steps 2–3 across N epochs without ever calling `claim_rewards`.
5. After N epochs, `claim_rewards` triggers `calculate_rewards`, which enters the loop at: [3](#0-2) 

   and must iterate all N entries in one transaction. For sufficiently large N, the transaction runs out of gas and reverts, permanently blocking reward withdrawal.

### Citations

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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L163-173)
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
```
