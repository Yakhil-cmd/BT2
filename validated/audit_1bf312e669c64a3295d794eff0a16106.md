### Title
Unbounded Loop in `calculate_rewards` Over User-Grown Balance Trace Permanently Freezes Unclaimed Yield - (File: `src/pool/pool.cairo`)

### Summary

The `calculate_rewards` function in the Pool contract contains an explicitly acknowledged unbounded loop that iterates over every entry in a pool member's `pool_member_epoch_balance` trace. Because a delegator can grow this trace by making balance changes across many epochs, a sufficiently active delegator will eventually cause every `claim_rewards` call to exceed the Starknet transaction gas limit, permanently freezing their unclaimed yield.

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` iterates over the entire `pool_member_epoch_balance` trace from `entry_to_claim_from` to the current trace length:

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
    entry_to_claim_from += 1;
}
```

The trace grows via `set_member_balance`, which calls `trace.insert(key: self.get_epoch_plus_k(), value: ...)`. The `insert` implementation in `src/pool/pool_member_balance_trace/trace.cairo` **appends a new checkpoint** whenever the key (`current_epoch + K`) differs from the last stored key — i.e., whenever a balance-modifying call is made in a new epoch:

```cairo
} else {
    assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
```

Every call to `add_to_delegation_pool` (line 242) or `exit_delegation_pool_intent` (line 278) in a distinct epoch appends one new entry. The `entry_to_claim_from` cursor is only advanced by a successful `claim_rewards` call. If a delegator makes N balance changes across N epochs without claiming, the next `claim_rewards` call must iterate all N entries in a single transaction.

### Impact Explanation

Once the trace is large enough that iterating it exhausts the Starknet per-transaction gas limit, every subsequent `claim_rewards` call reverts. The `entry_to_claim_from` cursor is never advanced (it is only written on success), so the state is permanently stuck. The delegator's accumulated STRK rewards are irrecoverable — **permanent freezing of unclaimed yield**.

The principal (delegated tokens) is unaffected; only the yield is frozen.

### Likelihood Explanation

- Any unprivileged delegator triggers this through normal protocol interactions (`add_to_delegation_pool`, `exit_delegation_pool_intent`).
- Each loop iteration performs at least one storage read (`pool_member_trace.at(...)`) plus a `find_sigma` call (additional storage reads into `cumulative_rewards_trace`). On Starknet, storage reads are among the most expensive operations. A few thousand iterations is sufficient to exhaust the gas budget.
- A delegator who actively manages their position (partial exits, top-ups) across hundreds of epochs — a realistic multi-year scenario — will accumulate enough trace entries to trigger this.
- The developers themselves acknowledge the loop is unbounded (the comment at line 857–858 reads: *"This loop is unbounded but unlikely to exceed gas limits"*), confirming awareness of the risk.

### Recommendation

Introduce a per-call iteration cap in `calculate_rewards` and allow partial reward claims that advance `entry_to_claim_from` incrementally across multiple transactions. Alternatively, restructure the reward accounting to avoid iterating the full balance history on each claim (e.g., by snapshotting cumulative rewards at each balance-change epoch so that a single lookup suffices regardless of trace length).

### Proof of Concept

1. Staker stakes and opens a pool.
2. Delegator calls `enter_delegation_pool` with the minimum amount.
3. For each of N epochs, the delegator calls `add_to_delegation_pool` with 1 unit. Each call in a new epoch appends one entry to `pool_member_epoch_balance` (since `get_epoch_plus_k()` returns a strictly larger key each epoch). The delegator never calls `claim_rewards`, so `entry_to_claim_from` remains 0.
4. After N epochs, the delegator (or their reward address) calls `claim_rewards`. `calculate_rewards` enters the loop and iterates all N entries, each requiring storage reads into both `pool_member_epoch_balance` and `cumulative_rewards_trace`. For sufficiently large N, the transaction runs out of gas and reverts.
5. Because the revert prevents `entry_to_claim_from` from being updated, every future `claim_rewards` call also reverts. The delegator's yield is permanently frozen.

**Relevant code locations:**

- Unbounded loop: [1](#0-0) 
- Trace append on balance change: [2](#0-1) 
- `set_member_balance` using `get_epoch_plus_k()` as key: [3](#0-2) 
- `add_to_delegation_pool` calling `increase_member_balance`: [4](#0-3) 
- `exit_delegation_pool_intent` calling `set_member_balance`: [5](#0-4) 
- `claim_rewards` invoking `calculate_rewards` with stored `entry_to_claim_from`: [6](#0-5)

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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L169-173)
```text
        } else {
            // Checkpoint keys must be non-decreasing.
            assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
            checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
        }
```
