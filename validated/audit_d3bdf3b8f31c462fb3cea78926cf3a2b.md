### Title
Unbounded Loop in `calculate_rewards` Over `pool_member_epoch_balance` Trace Can Permanently Freeze Delegator's Unclaimed Yield - (File: src/pool/pool.cairo)

---

### Summary

The `calculate_rewards` function in `src/pool/pool.cairo` contains an explicitly acknowledged unbounded loop that iterates over every entry in a pool member's `pool_member_epoch_balance` trace since their last claim. Because there is no cap on how many entries can accumulate in this trace, a delegator who makes many balance changes across different epochs without claiming rewards will eventually be unable to call `claim_rewards` — the transaction will exceed Starknet's resource/step limits, permanently freezing their unclaimed yield.

---

### Finding Description

**Root cause — unbounded loop in `calculate_rewards`:**

In `src/pool/pool.cairo` lines 857–877, the code itself documents the risk:

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

**How the trace grows unboundedly:**

Every call to `set_member_balance` inserts a new checkpoint into `pool_member_epoch_balance` keyed by `current_epoch + K`. The `insert` function in the trace only merges with the last entry if the epoch key is identical; otherwise it appends a new checkpoint:

```cairo
} else {
    // Checkpoint keys must be non-decreasing.
    assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
``` [2](#0-1) 

`set_member_balance` is called by both `increase_member_balance` (used in `add_to_delegation_pool`) and directly in `exit_delegation_pool_intent`: [3](#0-2) [4](#0-3) 

Each balance change in a distinct epoch appends one new entry. There is no maximum trace length enforced anywhere.

**Why `entry_to_claim_from` does not save the delegator:**

`entry_to_claim_from` is stored in `pool_member_info` and is advanced only upon a *successful* `claim_rewards` call:

```cairo
pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
``` [5](#0-4) 

If the loop is already too large to complete within the transaction resource limit, the claim reverts, `entry_to_claim_from` is never updated, and the delegator is permanently locked out of their rewards. There is no partial-claim mechanism.

---

### Impact Explanation

A delegator who makes many balance changes across different epochs without claiming rewards accumulates a large `pool_member_epoch_balance` trace. When `claim_rewards` is eventually called, the loop must process every accumulated entry in a single transaction. If the trace is large enough to exceed Starknet's per-transaction step/resource limit, the transaction reverts. Because `entry_to_claim_from` is only advanced on success, the delegator can never reduce the loop size — their unclaimed STRK rewards are permanently frozen in the pool contract.

This matches the allowed impact: **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

The scenario does not require a malicious actor. Any delegator who:
1. Actively adjusts their delegation (adds or partially exits) across many different epochs, AND
2. Does not claim rewards frequently enough

will organically accumulate a large trace. The protocol has no minimum claim frequency requirement and no cap on balance-change frequency. The comment in the code ("unlikely to exceed gas limits") acknowledges the risk but provides no enforcement. On Starknet, where transaction resource limits are finite and well-defined, a sufficiently large trace will trigger the failure.

---

### Recommendation

1. **Cap the trace length** by enforcing a `MAX_BALANCE_CHANGES` constant (analogous to the `MAX_DELEGATES` fix in the referenced report). Reject `add_to_delegation_pool` and `exit_delegation_pool_intent` calls that would push the trace beyond this cap.
2. **Alternatively, force a claim before each balance change** so that `entry_to_claim_from` is always advanced to the current trace length before a new entry is appended, keeping the loop bounded to at most 1–2 entries per call.
3. **Or implement partial claiming** so that `claim_rewards` can be called multiple times, each time processing a bounded slice of the trace, until all rewards are claimed.

---

### Proof of Concept

```
1. Staker stakes and opens a STRK delegation pool.
2. Delegator delegates a minimum amount.
3. For N epochs (e.g., N = 10,000):
   a. Advance one epoch.
   b. Call add_to_delegation_pool(pool_member, 1) — appends one new entry to
      pool_member_epoch_balance trace.
   (Do NOT call claim_rewards during this loop.)
4. After N epochs, call claim_rewards(pool_member).
   → The calculate_rewards loop must iterate N times, each iteration calling
     find_sigma (a storage read) and compute_rewards_rounded_down.
   → The transaction exceeds Starknet's step limit and reverts.
5. entry_to_claim_from remains at 0. All subsequent claim_rewards calls also revert.
   The delegator's accumulated rewards are permanently frozen.
```

The `calculate_rewards` function is called from `claim_rewards` at: [6](#0-5)

### Citations

**File:** src/pool/pool.cairo (L277-279)
```text
            // Update the pool member's balance checkpoint.
            self.set_member_balance(:pool_member, amount: new_delegated_stake);

```

**File:** src/pool/pool.cairo (L349-355)
```text
            let (mut rewards, updated_entry_to_claim_from) = self
                .calculate_rewards(
                    :pool_member,
                    from_checkpoint: pool_member_info.reward_checkpoint,
                    :until_checkpoint,
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
```

**File:** src/pool/pool.cairo (L358-359)
```text
            pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
            pool_member_info.reward_checkpoint = until_checkpoint;
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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L169-173)
```text
        } else {
            // Checkpoint keys must be non-decreasing.
            assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
            checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
        }
```
