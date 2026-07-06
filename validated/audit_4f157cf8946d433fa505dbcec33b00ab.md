### Title
Unbounded Loop in `calculate_rewards` Over `pool_member_epoch_balance` Trace Can Permanently Freeze Unclaimed Yield - (File: `src/pool/pool.cairo`)

### Summary
The `calculate_rewards` internal function in the Pool contract iterates over every entry in a pool member's `pool_member_epoch_balance` trace between two checkpoints. Because there is no cap on how many balance-change entries a pool member can accumulate across epochs, a pool member who makes many balance changes without claiming rewards can grow this trace unboundedly. Once the trace is large enough, the `claim_rewards` call will always revert due to out-of-gas, permanently freezing the pool member's unclaimed yield.

### Finding Description
`calculate_rewards` in `src/pool/pool.cairo` contains an explicit unbounded `while` loop:

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

The loop iterates over all entries in `pool_member_epoch_balance` (the per-member balance trace) from `entry_to_claim_from` up to the current epoch. Each time a pool member calls `add_to_delegation_pool` or `exit_delegation_pool_intent` in a new epoch, a new entry is appended to this trace. The `entry_to_claim_from` cursor is only advanced after a successful `claim_rewards` call; if the member never claims (or claims infrequently), the number of unprocessed entries grows without bound.

The code itself acknowledges this with the comment: *"This loop is unbounded but unlikely to exceed gas limits."* — but this is an assumption, not an enforced invariant. [2](#0-1) 

### Impact Explanation
Once the `pool_member_epoch_balance` trace for a given pool member grows large enough, every call to `claim_rewards` for that member will exceed the Starknet transaction gas limit and revert. Because:
- There is no mechanism to partially process the trace across multiple transactions.
- There is no mechanism to prune or reset the trace.
- The `entry_to_claim_from` cursor is only updated on a *successful* completion of `calculate_rewards`.

The pool member's accumulated rewards become permanently unclaimable — **permanent freezing of unclaimed yield**.

This matches the allowed impact: **High — Permanent freezing of unclaimed yield or unclaimed royalties**.

### Likelihood Explanation
Any pool member (unprivileged) can trigger this by repeatedly calling `add_to_delegation_pool` or `exit_delegation_pool_intent` across many different epochs without claiming rewards. Each such call in a new epoch appends one entry to the trace. A pool member who participates actively over hundreds of epochs without claiming will naturally accumulate a large trace. No special privileges or external dependencies are required — only normal pool member interactions. [3](#0-2) 

### Recommendation
Enforce an upper bound on the number of unclaimed balance-change entries a pool member may accumulate before being required to claim rewards. For example:
- Cap the number of entries processed per `claim_rewards` call and allow partial claims (advancing `entry_to_claim_from` across multiple transactions).
- Or enforce a maximum number of balance changes per epoch or between claims, reverting `add_to_delegation_pool` / `exit_delegation_pool_intent` if the trace would exceed the cap.

This mirrors the fix applied in the referenced report: introducing an explicit upper bound (e.g., `12`) on the unbounded collection.

### Proof of Concept
1. Pool member Alice calls `add_to_delegation_pool` once per epoch for 500 consecutive epochs, never calling `claim_rewards`. Each call appends one entry to `pool_member_epoch_balance` for Alice.
2. After 500 epochs, Alice calls `claim_rewards`.
3. `calculate_rewards` is invoked with `entry_to_claim_from = 0` and `pool_member_trace_length = 500`.
4. The `while` loop executes up to 500 iterations, each calling `self.find_sigma(...)` (which itself reads from storage).
5. The cumulative gas cost of 500 storage-reading iterations exceeds the Starknet per-transaction gas limit.
6. The transaction reverts. Alice's `entry_to_claim_from` cursor is not advanced. Every subsequent `claim_rewards` attempt also reverts. Alice's yield is permanently frozen. [4](#0-3)

### Citations

**File:** src/pool/pool.cairo (L844-851)
```text
            let pool_member_trace = self.pool_member_epoch_balance.entry(pool_member);
            // Note: `until_epoch` is the current epoch.
            let until_epoch = until_checkpoint.epoch();

            let mut rewards = 0;

            let pool_member_trace_length = pool_member_trace.length();

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
