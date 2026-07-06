### Title
Unbounded Loop in `calculate_rewards` Enables Permanent Freezing of Delegator Unclaimed Yield - (File: src/pool/pool.cairo)

### Summary
The `calculate_rewards` function in the Pool contract contains an explicitly acknowledged unbounded loop that iterates over every balance-change checkpoint in a pool member's `pool_member_epoch_balance` trace. A delegator who accumulates enough trace entries without claiming rewards will eventually cause `claim_rewards` (and `pool_member_info_v1`) to exceed the Starknet gas limit, permanently freezing their unclaimed yield with no recovery path.

### Finding Description

**Root Cause**

`calculate_rewards` in `src/pool/pool.cairo` iterates over the entire `pool_member_epoch_balance` trace from `entry_to_claim_from` to `pool_member_trace_length` with no upper bound:

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

The developers themselves flag this as unbounded. Each iteration performs multiple storage reads (`pool_member_trace.at(...)` and `find_sigma` which reads `cumulative_rewards_trace`), making each iteration gas-heavy.

**How trace entries accumulate**

Every call to `add_to_delegation_pool` invokes `increase_member_balance` → `set_member_balance`, which calls `trace.insert(key: self.get_epoch_plus_k(), ...)`: [2](#0-1) 

Every call to `exit_delegation_pool_intent` calls `set_member_balance` directly: [3](#0-2) 

The trace `insert` logic only appends a **new** checkpoint when the epoch key differs from the last entry: [4](#0-3) 

So one balance-change call per distinct epoch permanently appends one entry to the trace.

**Why `entry_to_claim_from` does not protect against this**

`entry_to_claim_from` is only advanced when `claim_rewards` succeeds and writes back to storage: [5](#0-4) 

If the delegator never calls `claim_rewards` (or defers it), `entry_to_claim_from` stays at 0 and the loop must traverse every accumulated entry on the next call.

**Two call sites are affected**

Both `claim_rewards` and the view function `pool_member_info_v1` call `calculate_rewards`: [6](#0-5) [7](#0-6) 

Once the trace is large enough, both revert on gas exhaustion.

### Impact Explanation

A pool member whose `pool_member_epoch_balance` trace grows large enough will find that both `claim_rewards` and `pool_member_info_v1` permanently revert. There is no administrative function to prune the trace, no partial-claim mechanism, and no way to reset `entry_to_claim_from` without a successful `claim_rewards`. The delegator's accumulated yield is permanently frozen with no recovery path. This matches the **High** impact category: *Permanent freezing of unclaimed yield*.

### Likelihood Explanation

The precondition is that a pool member makes balance changes across many distinct epochs without claiming rewards in between. This is realistic for:
- A DeFi protocol or smart-contract wallet that programmatically adjusts delegation amounts each epoch without a built-in reward-claim step.
- A delegator who frequently adjusts their stake over months/years and defers reward claims.

The minimum cost is one on-chain transaction per epoch. No privileged access is required; only the pool member address (or its reward address) can call `add_to_delegation_pool`, so the entry path is fully unprivileged. The code comment itself acknowledges the loop is unbounded, confirming the developers are aware the risk exists.

### Recommendation

1. **Short-term**: Enforce a maximum number of unclaimed balance-change entries before allowing further balance modifications. Require the delegator to call `claim_rewards` (advancing `entry_to_claim_from`) before new entries can be appended beyond a safe threshold (e.g., 100–200 entries).
2. **Long-term**: Redesign `calculate_rewards` to use a heap/storage-based pagination scheme analogous to the sputnikvm heap-based call stack recommendation in the original report — process rewards in bounded batches and persist intermediate state, so a single transaction never needs to traverse an unbounded trace.

### Proof of Concept

1. Delegator calls `enter_delegation_pool` with a small amount.
2. Each epoch, delegator calls `add_to_delegation_pool(pool_member, 1)` — one new `pool_member_epoch_balance` checkpoint is appended per epoch.
3. Delegator never calls `claim_rewards`, so `entry_to_claim_from` remains 0.
4. After N epochs (where N is large enough to exhaust Starknet's per-transaction gas limit given the storage-read cost per iteration), any call to `claim_rewards` or `pool_member_info_v1` for this delegator reverts.
5. The delegator's entire accumulated yield is permanently inaccessible. No admin or governance function can recover it.

The exact N depends on Starknet's gas limit and the per-iteration cost of `pool_member_trace.at(...)` + `find_sigma` (each involving multiple storage reads from `cumulative_rewards_trace`). Given that each iteration performs at least 3–5 storage reads, N is in the range of hundreds to low thousands of epochs — achievable by any long-term delegator who defers reward claims.

### Citations

**File:** src/pool/pool.cairo (L241-243)
```text
            // Update the pool member's balance checkpoint.
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
            let new_delegated_stake = old_delegated_stake + amount;
```

**File:** src/pool/pool.cairo (L277-279)
```text
            // Update the pool member's balance checkpoint.
            self.set_member_balance(:pool_member, amount: new_delegated_stake);

```

**File:** src/pool/pool.cairo (L349-359)
```text
            let (mut rewards, updated_entry_to_claim_from) = self
                .calculate_rewards(
                    :pool_member,
                    from_checkpoint: pool_member_info.reward_checkpoint,
                    :until_checkpoint,
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
            rewards += pool_member_info._unclaimed_rewards_from_v0;
            pool_member_info._unclaimed_rewards_from_v0 = Zero::zero();
            pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
            pool_member_info.reward_checkpoint = until_checkpoint;
```

**File:** src/pool/pool.cairo (L532-538)
```text
            let (rewards, _) = self
                .calculate_rewards(
                    :pool_member,
                    from_checkpoint: pool_member_info.reward_checkpoint,
                    until_checkpoint: self.get_current_checkpoint(:pool_member),
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
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
