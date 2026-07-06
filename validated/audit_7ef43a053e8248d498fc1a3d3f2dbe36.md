### Title
Unbounded `pool_member_epoch_balance` Trace Causes Permanent Freezing of Pool Member Rewards - (File: `src/pool/pool.cairo`)

### Summary

The `calculate_rewards` function in `src/pool/pool.cairo` iterates over every entry in a pool member's `pool_member_epoch_balance` trace without any bound. Because every balance change (deposit or exit-intent) in a new epoch appends a new checkpoint to this trace, a pool member who makes many balance changes across many epochs will eventually cause `claim_rewards` to exceed the Starknet transaction gas limit, permanently freezing their unclaimed yield. The codebase itself acknowledges the risk with an inline comment.

### Finding Description

`calculate_rewards` (pool.cairo:837–888) drives reward computation for `claim_rewards` (pool.cairo:335–377) and `pool_member_info_v1` (pool.cairo:528–548). It reads the full `pool_member_epoch_balance` trace for the caller and iterates from `entry_to_claim_from` to `pool_member_trace_length`:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    ...
    entry_to_claim_from += 1;
}
```

The trace grows via `set_member_balance` (pool.cairo:718–729), which calls `trace.insert(key: self.get_epoch_plus_k(), value: ...)`. The `insert` implementation (trace.cairo:152–175) either overwrites the last checkpoint if the key matches, or **appends a new checkpoint** when the key is different. Because `get_epoch_plus_k()` returns `current_epoch + K`, every balance change made in a different epoch appends a distinct entry. There is no pruning, no cap, and no pagination.

Two public entry points grow the trace:
- `add_to_delegation_pool` → `increase_member_balance` → `set_member_balance` → `trace.insert`
- `exit_delegation_pool_intent` → `set_member_balance` → `trace.insert`

Both are callable by any pool member with no privileged role.

### Impact Explanation

Once the trace is large enough, every call to `claim_rewards` (and `pool_member_info_v1`) will revert with an out-of-gas error. Because `entry_to_claim_from` is only advanced inside a successful `claim_rewards` execution, a failed call makes no progress. The pool member's accumulated STRK rewards become permanently inaccessible — they cannot be claimed, and there is no administrative escape hatch to reset or paginate the trace.

**Impact: High — Permanent freezing of unclaimed yield.**

### Likelihood Explanation

Any pool member (unprivileged delegator) can trigger this by repeatedly calling `add_to_delegation_pool` or `exit_delegation_pool_intent` across many epochs. This is normal protocol usage (active delegation management). No special capital is required beyond the minimum delegation amount, and the cost is only the gas for each balance-change transaction. A motivated attacker can self-inflict this to grief their own rewards, or a long-lived honest delegator who actively manages their position will hit this organically over time.

### Recommendation

1. **Paginate `calculate_rewards`**: Accept a `max_iterations` parameter and return a partial result with an updated `entry_to_claim_from`, allowing the caller to resume in subsequent transactions.
2. **Checkpoint on claim**: Advance `entry_to_claim_from` and update `reward_checkpoint` at the end of each successful partial claim so progress is never lost.
3. **Alternatively, compress the trace**: When two consecutive entries in the trace fall within the same reward-accounting window, merge them to bound trace growth.

### Proof of Concept

1. Pool member Alice calls `add_to_delegation_pool` once per epoch for N epochs (N ≫ 1), each time with a small amount so the call succeeds. Each call lands in a new epoch, so `trace.insert` appends a new `PoolMemberBalanceCheckpoint` (trace.cairo:172).
2. After N epochs, `pool_member_epoch_balance.length()` for Alice equals N.
3. Alice calls `claim_rewards`. `calculate_rewards` enters the `while` loop and must iterate all N entries before returning.
4. For sufficiently large N (determined by Starknet's per-transaction gas cap), the transaction reverts with out-of-gas.
5. Every subsequent `claim_rewards` call also reverts because `entry_to_claim_from` was never committed. Alice's rewards are permanently frozen.

---

**Root cause:** `calculate_rewards` unbounded loop over `pool_member_epoch_balance` trace. [1](#0-0) 

**Trace growth:** `set_member_balance` appends a new checkpoint per epoch via `trace.insert`. [2](#0-1) 

**Insert logic:** New checkpoint appended when key differs from last entry. [3](#0-2) 

**Trigger path 1:** `add_to_delegation_pool` → `increase_member_balance` → `set_member_balance`. [4](#0-3) 

**Trigger path 2:** `exit_delegation_pool_intent` → `set_member_balance`. [5](#0-4) 

**Reward freeze:** `claim_rewards` calls `calculate_rewards` and only commits `entry_to_claim_from` on success. [6](#0-5)

### Citations

**File:** src/pool/pool.cairo (L241-243)
```text
            // Update the pool member's balance checkpoint.
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
            let new_delegated_stake = old_delegated_stake + amount;
```

**File:** src/pool/pool.cairo (L277-278)
```text
            // Update the pool member's balance checkpoint.
            self.set_member_balance(:pool_member, amount: new_delegated_stake);
```

**File:** src/pool/pool.cairo (L349-358)
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
```

**File:** src/pool/pool.cairo (L718-729)
```text
        fn set_member_balance(
            ref self: ContractState, pool_member: ContractAddress, amount: Amount,
        ) {
            let trace = self.pool_member_epoch_balance.entry(pool_member);
            // `cumulative_rewards_trace_idx` should be set to
            // `self.cumulative_rewards_trace_length() + (K - 1)`.
            let pool_member_balance = PoolMemberBalanceTrait::new(
                balance: amount,
                cumulative_rewards_trace_idx: self.cumulative_rewards_trace_length() + 1,
            );
            trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance);
        }
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
