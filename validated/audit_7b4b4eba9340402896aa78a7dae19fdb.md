### Title
Unbounded `pool_member_epoch_balance` Trace Growth Causes Permanent Freezing of Unclaimed Yield via OOG in `calculate_rewards` - (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` function in `Pool` iterates over every entry in a pool member's `pool_member_epoch_balance` trace since their last claim. This trace grows by one entry per epoch whenever the pool member changes their balance. Because there is no cap on trace length and no mechanism to prune old entries, a pool member who makes balance changes across many epochs without claiming rewards will eventually cause `claim_rewards` (and `pool_member_info_v1`) to permanently revert out-of-gas, freezing their unclaimed yield forever.

---

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` contains an explicitly acknowledged unbounded loop:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch { break; }
    ...
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

The loop iterates from `entry_to_claim_from` (the index saved at the last successful `claim_rewards`) up to the current trace length. Each iteration performs at least one storage read (`pool_member_trace.at(...)`) plus a `find_sigma` call.

The trace is grown by `set_member_balance`, which calls `trace.insert(key: self.get_epoch_plus_k(), ...)`. The `insert` implementation only appends a **new** checkpoint when the epoch key differs from the last entry's key — i.e., at most once per epoch. [2](#0-1) [3](#0-2) 

`set_member_balance` is called from:
- `enter_delegation_pool` (line 201)
- `add_to_delegation_pool` via `increase_member_balance` (line 242)
- `exit_delegation_pool_intent` (line 278) [4](#0-3) [5](#0-4) [6](#0-5) 

Both `add_to_delegation_pool` and `exit_delegation_pool_intent` are callable by the pool member (or their reward address) with no rate limit beyond the epoch boundary. A pool member who makes one balance change per epoch and defers claiming rewards accumulates one new trace entry per epoch indefinitely.

`entry_to_claim_from` is only advanced inside `claim_rewards` and is never advanced by `pool_member_info_v1`. If the pool member never calls `claim_rewards`, the loop must traverse the entire trace from the beginning on every call. [7](#0-6) [8](#0-7) 

---

### Impact Explanation

Once the trace is large enough that iterating it exceeds Starknet's per-transaction gas limit, every call to `claim_rewards` and `pool_member_info_v1` will revert out-of-gas. Because there is no mechanism to prune the trace or split the claim into batches, the pool member's accumulated unclaimed yield is **permanently frozen** — it can never be transferred to the reward address.

**Impact class:** Permanent freezing of unclaimed yield (High).

---

### Likelihood Explanation

The attack requires the pool member to:
1. Make at least one balance change per epoch (via `add_to_delegation_pool` with a minimal non-zero amount, or via `exit_delegation_pool_intent`/re-entry cycling).
2. Defer calling `claim_rewards` for a large number of epochs.

This is a realistic long-term scenario for active delegators who adjust their position frequently. The protocol is designed to run indefinitely; over years of operation, a pool member who adjusts delegation every epoch without claiming will naturally accumulate thousands of trace entries. The codebase itself acknowledges the risk with the comment "This loop is unbounded but unlikely to exceed gas limits," which is an incorrect assumption over protocol lifetime timescales.

No privileged access is required. The pool member address alone is sufficient.

---

### Recommendation

1. **Enforce periodic claiming:** Require or incentivize `claim_rewards` to be called before `add_to_delegation_pool` or `exit_delegation_pool_intent` if the unclaimed trace window exceeds a threshold (e.g., 100 entries).
2. **Paginated claiming:** Expose a `claim_rewards_partial(max_entries)` entry point that advances `entry_to_claim_from` by at most `max_entries` per call, allowing the pool member to drain the trace over multiple transactions.
3. **Trace compaction:** When `claim_rewards` is called, truncate or compact already-processed entries so the trace does not grow without bound.

---

### Proof of Concept

```
Epoch 1:  pool_member calls enter_delegation_pool(amount=MIN)
          → trace length = 1, entry_to_claim_from = 0

Epoch 2:  pool_member calls add_to_delegation_pool(amount=1)
          → trace length = 2

Epoch 3:  pool_member calls add_to_delegation_pool(amount=1)
          → trace length = 3

... (repeat for N epochs without calling claim_rewards) ...

Epoch N:  trace length = N, entry_to_claim_from = 0

pool_member calls claim_rewards:
  → calculate_rewards loops from 0 to N-1
  → each iteration: storage read (pool_member_trace.at) + find_sigma (storage read)
  → total storage reads ≈ 2N
  → for sufficiently large N, transaction exceeds gas limit → REVERT

pool_member's unclaimed yield is permanently frozen.
```

The cost to grow the trace is one `add_to_delegation_pool` call per epoch with `amount=1`, which is the minimum non-zero amount. The attacker (the pool member themselves, or their reward address) spends only gas and 1 token unit per epoch to reach the threshold.

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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L152-174)
```text
    fn insert(
        self: StoragePath<Mutable<PoolMemberBalanceTrace>>, key: Epoch, value: PoolMemberBalance,
    ) -> (PoolMemberBalance, PoolMemberBalance) {
        let checkpoints = self.checkpoints;

        let len = checkpoints.len();
        if len == Zero::zero() {
            checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
            return (Zero::zero(), value);
        }

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
```
