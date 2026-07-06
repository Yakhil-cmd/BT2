### Title
Unbounded Loop Over `pool_member_epoch_balance` Trace in `calculate_rewards` Can Permanently Freeze Delegator Unclaimed Yield - (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` internal function in `src/pool/pool.cairo` contains an explicitly acknowledged unbounded loop that iterates over every entry in a delegator's `pool_member_epoch_balance` trace since their last claim. Because each call to `add_to_delegation_pool`, `exit_delegation_pool_intent`, or `enter_delegation_pool` in a distinct epoch appends a new checkpoint to this trace, a delegator who makes many balance changes across different epochs without claiming will accumulate an unbounded number of trace entries. Once the trace is large enough, the `claim_rewards` transaction will always exceed the Starknet gas limit and revert, permanently freezing the delegator's unclaimed yield with no recovery path.

---

### Finding Description

In `src/pool/pool.cairo`, the `calculate_rewards` function iterates over the entire `pool_member_epoch_balance` trace from `entry_to_claim_from` to `pool_member_trace_length`:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch {
        break;
    }
    let to_sigma = self.find_sigma(pool_member_checkpoint, curr_epoch: until_epoch);
    // ...
    entry_to_claim_from += 1;
}
```

The developers themselves flag this as unbounded. [1](#0-0) 

Each call to `set_member_balance` inserts a new checkpoint keyed at `current_epoch + K` into the trace. The `insert` function only deduplicates if the **same** epoch key is reused; a balance change in any different epoch appends a fresh entry:

```cairo
fn set_member_balance(ref self: ContractState, pool_member: ContractAddress, amount: Amount) {
    let trace = self.pool_member_epoch_balance.entry(pool_member);
    let pool_member_balance = PoolMemberBalanceTrait::new(
        balance: amount,
        cumulative_rewards_trace_idx: self.cumulative_rewards_trace_length() + 1,
    );
    trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance);
}
``` [2](#0-1) 

`set_member_balance` is called by `enter_delegation_pool`, `add_to_delegation_pool`, and `exit_delegation_pool_intent`. [3](#0-2) [4](#0-3) [5](#0-4) 

The `insert` function in `PoolMemberBalanceTrace` appends a new checkpoint whenever the key differs from the last:

```cairo
if last.key == key {
    last.value = value;
    checkpoints[len - 1].write(last);
} else {
    assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
``` [6](#0-5) 

Inside the loop, `find_sigma` is called for every checkpoint, which itself performs multiple storage reads against `cumulative_rewards_trace_vec`. [7](#0-6)  The per-iteration cost is therefore non-trivial (multiple storage reads per iteration).

The `entry_to_claim_from` cursor is only advanced and persisted upon a **successful** `claim_rewards` call. If the transaction reverts due to gas exhaustion, the cursor is never updated, and every subsequent `claim_rewards` attempt faces the same (or larger) loop, making the freeze permanent. There is no partial-claim or pagination mechanism in the `claim_rewards` interface. [8](#0-7) 

---

### Impact Explanation

A delegator who accumulates N balance-change entries across N distinct epochs without claiming will require O(N) storage reads (plus nested `find_sigma` reads) in a single `claim_rewards` call. Once N is large enough to exceed the Starknet per-transaction gas limit, every future `claim_rewards` call reverts. Because there is no way to claim a partial range of epochs or reset the cursor, all accumulated STRK rewards are **permanently frozen** in the pool contract and irrecoverable by the delegator.

This matches the allowed impact: **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

The entry path is fully unprivileged: any delegator can call `add_to_delegation_pool` (or `exit_delegation_pool_intent`) once per epoch to grow their trace by one entry per epoch. With epochs on the order of days, a delegator active for 1–3 years who never claims (or claims infrequently) can accumulate hundreds to thousands of entries. Given that each loop iteration involves multiple Starknet storage reads (which are among the most gas-expensive operations), a few thousand entries is sufficient to breach the gas limit. This is a realistic scenario for passive long-term delegators.

---

### Recommendation

1. **Paginated claiming**: Add a `claim_rewards_up_to(max_entries: u64)` variant that processes at most `max_entries` trace entries per call and persists the updated cursor, allowing delegators to drain their trace over multiple transactions.
2. **Bounded trace growth**: Periodically compact the `pool_member_epoch_balance` trace on each balance-change call (e.g., collapse all entries older than the last claimed checkpoint into a single entry), keeping the trace length proportional to the number of unclaimed epochs rather than the total lifetime of the delegator.
3. **Enforce a maximum trace depth**: Reject `add_to_delegation_pool` calls that would push the unclaimed trace length beyond a safe bound, forcing the delegator to claim first.

---

### Proof of Concept

1. Delegator Alice enters the pool at epoch E via `enter_delegation_pool`. Trace length = 1.
2. Alice calls `add_to_delegation_pool` once per epoch for N epochs without ever calling `claim_rewards`. Each call in a new epoch appends one entry. Trace length = N + 1.
3. After N epochs, Alice calls `claim_rewards`. The `calculate_rewards` loop iterates from `entry_to_claim_from = 0` to `pool_member_trace_length = N + 1`, calling `find_sigma` (multiple storage reads) on each iteration.
4. For sufficiently large N (empirically determinable from Starknet's gas table), the transaction exceeds the block gas limit and reverts.
5. Alice retries `claim_rewards`; the cursor was never updated, so the loop is identical. Every future attempt reverts.
6. Alice's entire accumulated STRK reward balance is permanently frozen in the pool contract. [1](#0-0) [9](#0-8) [2](#0-1)

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

**File:** src/pool/pool.cairo (L837-888)
```text
        fn calculate_rewards(
            self: @ContractState,
            pool_member: ContractAddress,
            from_checkpoint: PoolMemberCheckpoint,
            until_checkpoint: PoolMemberCheckpoint,
            mut entry_to_claim_from: VecIndex,
        ) -> (Amount, VecIndex) {
            let pool_member_trace = self.pool_member_epoch_balance.entry(pool_member);
            // Note: `until_epoch` is the current epoch.
            let until_epoch = until_checkpoint.epoch();

            let mut rewards = 0;

            let pool_member_trace_length = pool_member_trace.length();

            let mut from_sigma = self.find_sigma(from_checkpoint, curr_epoch: until_epoch);
            let mut from_balance = from_checkpoint.balance();

            let base_value = self.staking_rewards_base_value.read();

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

            // Compute the remaining rewards from (inclusive) the last visited balance change in
            // `pool_member_trace` (or from `from_checkpoint`) to (exclusive) `until_checkpoint`.
            let to_sigma = self.find_sigma(until_checkpoint, curr_epoch: until_epoch);
            rewards +=
                compute_rewards_rounded_down(
                    amount: from_balance, interest: to_sigma - from_sigma, :base_value,
                );

            (rewards, entry_to_claim_from)
        }
```

**File:** src/pool/pool_member_balance_trace/trace.cairo (L152-175)
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
    }
```
