### Title
Unbounded Loop in `calculate_rewards` Allows Permanent Freezing of Pool Member Unclaimed Yield - (File: src/pool/pool.cairo)

### Summary

The `calculate_rewards` function in `src/pool/pool.cairo` contains an explicitly acknowledged unbounded loop that iterates over a pool member's entire `pool_member_epoch_balance` trace. Because every call to `add_to_delegation_pool` or `exit_delegation_pool_intent` in a new epoch appends a new checkpoint to this trace, a pool member who accumulates enough balance-change entries without claiming rewards will cause `claim_rewards` (and the view `pool_member_info_v1`) to exceed Starknet's per-transaction gas limit, permanently freezing their unclaimed yield.

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` iterates over every entry in `pool_member_epoch_balance` from `entry_to_claim_from` to the current trace length:

```
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    ...
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

The trace grows because `set_member_balance` calls `trace.insert(key: self.get_epoch_plus_k(), ...)`. The underlying `insert` implementation only updates in-place when the key equals the last checkpoint's key; otherwise it **appends** a new checkpoint:

```rust
} else {
    assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
``` [2](#0-1) 

`set_member_balance` is called by both `add_to_delegation_pool` and `exit_delegation_pool_intent`: [3](#0-2) [4](#0-3) 

Because `set_member_balance` uses `get_epoch_plus_k()` as the key, each call in a distinct epoch appends a new entry. A pool member who makes one balance-change call per epoch without ever claiming rewards grows the trace by one entry per epoch, without bound. [5](#0-4) 

`entry_to_claim_from` is only advanced when `claim_rewards` succeeds and writes back to storage:

```rust
pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
``` [6](#0-5) 

If `claim_rewards` never succeeds (because it OOGs), `entry_to_claim_from` is never advanced, so every subsequent attempt re-iterates the same ever-growing range. The view function `pool_member_info_v1` also calls `calculate_rewards` without updating state, so it too will OOG: [7](#0-6) 

### Impact Explanation

Once the trace is large enough to cause an OOG in `calculate_rewards`, the pool member can never successfully call `claim_rewards`. Their accumulated yield is permanently locked in the contract with no recovery path. This matches the allowed impact: **Permanent freezing of unclaimed yield**.

### Likelihood Explanation

The attack requires only that a pool member call `add_to_delegation_pool` (minimum amount: 1 token) once per epoch without claiming rewards. This is a realistic pattern for a long-term delegator who delegates incrementally and defers reward collection. It can also be triggered deliberately by a griefing actor who controls a pool member address. The cost per epoch is a single transaction; over hundreds of epochs the trace grows to a size that exceeds the Starknet gas cap.

### Recommendation

1. **Short term**: Cap the number of trace entries processed per `claim_rewards` call. Introduce a `max_iterations` parameter (analogous to serde's `cautious(4096)` bound) and allow partial reward claims that advance `entry_to_claim_from` incrementally across multiple transactions.
2. **Long term**: Enforce a maximum trace length per pool member (e.g., by compacting old entries when `claim_rewards` is called), or require that rewards be claimed before each balance change, preventing unbounded accumulation.

### Proof of Concept

1. Staker stakes and opens a STRK delegation pool.
2. Pool member calls `enter_delegation_pool` with the minimum amount.
3. For each of N epochs (e.g., N = 2000), the pool member:
   - Advances to a new epoch.
   - Calls `add_to_delegation_pool` with amount = 1 (appends one new entry to `pool_member_epoch_balance`).
   - Does **not** call `claim_rewards`.
4. After N epochs, `pool_member_epoch_balance` has N entries.
5. Pool member calls `claim_rewards`. The `calculate_rewards` loop iterates N times, each iteration performing storage reads (`pool_member_trace.at(entry_to_claim_from)`) and a `find_sigma` call. The transaction runs out of gas and reverts.
6. Every subsequent call to `claim_rewards` also OOGs. The pool member's accumulated yield is permanently frozen.

The explicit developer comment at line 858 — *"This loop is unbounded but unlikely to exceed gas limits"* — confirms awareness of the issue but no mitigation is in place. [8](#0-7)

### Citations

**File:** src/pool/pool.cairo (L241-242)
```text
            // Update the pool member's balance checkpoint.
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
```

**File:** src/pool/pool.cairo (L277-278)
```text
            // Update the pool member's balance checkpoint.
            self.set_member_balance(:pool_member, amount: new_delegated_stake);
```

**File:** src/pool/pool.cairo (L358-359)
```text
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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L170-173)
```text
            // Checkpoint keys must be non-decreasing.
            assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
            checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
        }
```
