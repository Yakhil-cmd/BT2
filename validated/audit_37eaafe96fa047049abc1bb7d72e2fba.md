### Title
Unbounded Loop Over Pool Member Balance Trace Enables DoS on `claim_rewards` - (File: src/pool/pool.cairo)

### Summary
The `calculate_rewards` function in `pool.cairo` contains an explicitly acknowledged unbounded loop that iterates over a pool member's entire balance trace. A delegator can grow this trace without bound by repeatedly calling `add_to_delegation_pool` or `exit_delegation_pool_intent` across different epochs, eventually making `claim_rewards` (and `pool_member_info_v1`) permanently revert due to gas exhaustion.

### Finding Description
In `calculate_rewards`, the loop at line 859 iterates over every entry in `pool_member_epoch_balance` for a given pool member, from `entry_to_claim_from` up to the current trace length:

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
```

The trace grows by one entry each time `set_member_balance` is called with a new epoch key. `set_member_balance` is called by both `increase_member_balance` (used in `add_to_delegation_pool`) and directly in `exit_delegation_pool_intent`. The `insert` function in the trace only deduplicates entries with the **same** epoch key — a new entry is appended for every distinct epoch:

```cairo
} else {
    assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
```

Because `entry_to_claim_from` is only advanced and saved when `claim_rewards` is called successfully, a delegator who never claims (or whose claim always reverts) accumulates an ever-growing trace. Each call to `add_to_delegation_pool` or `exit_delegation_pool_intent` in a new epoch appends one entry. After enough epochs, the loop in `calculate_rewards` will consume more gas than the Starknet block gas limit, causing every future call to `claim_rewards` and `pool_member_info_v1` for that member to revert permanently.

The codebase itself acknowledges this risk with the comment: *"This loop is unbounded but unlikely to exceed gas limits."*

### Impact Explanation
Once the trace is large enough, `claim_rewards` permanently reverts for the targeted pool member. The member's accrued rewards are frozen in the pool contract and can never be withdrawn. This matches the allowed impact: **Permanent freezing of unclaimed yield** (High).

Additionally, `pool_member_info_v1` also calls `calculate_rewards` and would revert, making the member's state unreadable on-chain.

### Likelihood Explanation
A delegator can self-inflict this by repeatedly calling `add_to_delegation_pool` with a minimal amount (above the minimum) once per epoch, or by cycling `exit_delegation_pool_intent` with varying amounts across epochs. No privileged access is required — `add_to_delegation_pool` is callable by the pool member or their reward address. The cost is one transaction per epoch; over hundreds of epochs this is feasible. The protocol has no cap on the number of balance trace entries per member.

### Recommendation
1. Add a maximum cap on the number of entries in `pool_member_epoch_balance` per pool member (e.g., reject `add_to_delegation_pool` / `exit_delegation_pool_intent` if the trace length exceeds a safe bound).
2. Alternatively, require that `claim_rewards` is called (advancing `entry_to_claim_from`) before a new balance change is accepted, or enforce a minimum epoch gap between balance changes.
3. At minimum, document and enforce a protocol-level invariant on the maximum trace length and add a guard in `calculate_rewards` to break after a bounded number of iterations per call, allowing partial reward claims.

### Proof of Concept

1. Staker stakes with pool enabled.
2. Delegator calls `enter_delegation_pool` with amount `A`.
3. Each epoch, delegator calls `add_to_delegation_pool` with a small amount (e.g., 1 token), never calling `claim_rewards`. Each call appends a new entry to `pool_member_epoch_balance` via `set_member_balance` → `insert`.
4. After `N` epochs without claiming, the trace has `N` entries.
5. When `claim_rewards` is eventually called, `calculate_rewards` loops over all `N` entries. For sufficiently large `N`, the transaction exceeds the block gas limit and reverts.
6. All subsequent calls to `claim_rewards` also revert — the delegator's accumulated yield is permanently frozen.

**Relevant code locations:**

- Unbounded loop: [1](#0-0) 
- Trace insertion (one entry per distinct epoch): [2](#0-1) 
- `set_member_balance` called on every balance change: [3](#0-2) 
- `claim_rewards` calling `calculate_rewards`: [4](#0-3) 
- `pool_member_info_v1` also calling `calculate_rewards`: [5](#0-4)

### Citations

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
