### Title
Unbounded Loop in `calculate_rewards` Over `pool_member_epoch_balance` Trace Enables Permanent Freezing of Unclaimed Yield — (`File: src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` function in the Pool contract iterates over a delegator's entire `pool_member_epoch_balance` trace in an unbounded loop. Because every balance change in a new epoch appends a new entry to this trace with no cap or pruning, a delegator who makes many balance changes across many epochs without claiming rewards will eventually be unable to call `claim_rewards` — the transaction will exceed Starknet's gas limit, permanently freezing their unclaimed yield.

---

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` contains an explicitly acknowledged unbounded loop:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch {
        break;
    }
    ...
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

The loop iterates from `entry_to_claim_from` (the index saved at the last successful `claim_rewards`) up to the current trace length. Each iteration performs a storage read (`pool_member_trace.at(...)`) and a `find_sigma` call, both of which are non-trivial gas operations.

The trace grows via `set_member_balance`, which calls `trace.insert(key: self.get_epoch_plus_k(), ...)`. The underlying `insert` implementation only deduplicates if the key (epoch) is identical to the last entry; otherwise it appends a new checkpoint:

```cairo
if last.key == key {
    last.value = value;
    checkpoints[len - 1].write(last);
} else {
    assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
``` [2](#0-1) 

`set_member_balance` is called from every balance-mutating entry point:

- `enter_delegation_pool` — initial delegation [3](#0-2) 
- `add_to_delegation_pool` — increase delegation [4](#0-3) 
- `exit_delegation_pool_intent` — partial/full exit intent [5](#0-4) 
- `enter_delegation_pool_from_staking_contract` — pool switch [6](#0-5) 

Each call in a distinct epoch appends one new entry. There is no maximum trace length enforced anywhere, and old entries are never pruned.

`claim_rewards` passes `pool_member_info.entry_to_claim_from` as the loop start index, which is updated to the new position after a successful claim. This means the loop length equals the number of balance changes made since the last successful `claim_rewards` call. [7](#0-6) 

`pool_member_info_v1` (a view function) also calls `calculate_rewards` with the same unbounded loop, so even read queries can fail. [8](#0-7) 

---

### Impact Explanation

If a delegator accumulates enough balance-change entries between two `claim_rewards` calls, the loop will exceed Starknet's per-transaction gas limit. Because `entry_to_claim_from` is only advanced on a *successful* `claim_rewards`, and the trace is never pruned, the call will fail on every subsequent attempt. The delegator's accrued rewards are permanently frozen and unrecoverable.

**Impact: Permanent freezing of unclaimed yield (High).**

---

### Likelihood Explanation

The scenario requires a delegator to:
1. Make balance changes (via `add_to_delegation_pool` or `exit_delegation_pool_intent`) across many distinct epochs.
2. Not call `claim_rewards` between those changes.

This is a realistic usage pattern — a delegator who actively manages their position (e.g., dollar-cost averaging in, or repeatedly adjusting their exit intent) over a long period without claiming. The protocol itself acknowledges the loop is unbounded. The number of epochs required to hit the gas limit depends on Starknet's block gas limit, but given each loop iteration involves multiple storage reads, the threshold is reachable in practice.

**Likelihood: Medium.**

---

### Recommendation

1. **Enforce a maximum trace length per pool member.** Reject `add_to_delegation_pool` / `exit_delegation_pool_intent` calls if the trace would exceed a safe bound (e.g., 500 entries).
2. **Alternatively, require `claim_rewards` before balance changes** if the trace exceeds a threshold, forcing the delegator to flush accumulated entries before adding new ones.
3. **Prune consumed entries.** After `claim_rewards` advances `entry_to_claim_from`, entries before that index are no longer needed. Removing them would keep the active window bounded, though Cairo's `Vec` storage does not support efficient front-deletion today.
4. **Remove the comment** "unlikely to exceed gas limits" — it is a known risk that should be mitigated, not dismissed.

---

### Proof of Concept

1. Deploy the staking system and have a staker open a pool.
2. As a delegator, call `enter_delegation_pool` with a small amount.
3. In a loop: advance one epoch, then call `add_to_delegation_pool` with 1 token. Repeat N times (e.g., N = 1000) without ever calling `claim_rewards`.
4. Each iteration appends one entry to `pool_member_epoch_balance` because `get_epoch_plus_k()` returns a strictly increasing key each epoch.
5. After N iterations, call `claim_rewards`. The loop in `calculate_rewards` must iterate N times, each reading from storage. At a sufficient N, the transaction runs out of gas and reverts.
6. Because `entry_to_claim_from` was never updated (the transaction always reverts), all subsequent `claim_rewards` calls also revert — the yield is permanently frozen.

The code comment at line 858 of `src/pool/pool.cairo` explicitly acknowledges this risk:

> "This loop is unbounded but unlikely to exceed gas limits." [9](#0-8)

### Citations

**File:** src/pool/pool.cairo (L201-201)
```text
            self.set_member_balance(:pool_member, :amount);
```

**File:** src/pool/pool.cairo (L242-242)
```text
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
```

**File:** src/pool/pool.cairo (L278-278)
```text
            self.set_member_balance(:pool_member, amount: new_delegated_stake);
```

**File:** src/pool/pool.cairo (L348-358)
```text
            // Calculate rewards and update entry_to_claim_from.
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

**File:** src/pool/pool.cairo (L456-464)
```text
                    self.increase_member_balance(:pool_member, :amount);
                    VInternalPoolMemberInfoTrait::wrap_latest(value: pool_member_info)
                },
                Option::None => {
                    // Pool member does not exist. Create a new record.
                    let reward_address = switch_pool_data.reward_address;

                    // Update the pool member's balance checkpoint.
                    self.set_member_balance(:pool_member, :amount);
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
