### Title
Unbounded iteration over `pool_member_epoch_balance` trace in `calculate_rewards` enables permanent freezing of pool member unclaimed yield - (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` function in `src/pool/pool.cairo` iterates over every entry in a pool member's `pool_member_epoch_balance` trace since their last reward claim. There is no cap on how many entries can accumulate — one new entry is appended per epoch in which a balance change occurs. A pool member who makes one minimal balance change per epoch while never claiming rewards will grow this trace without bound. Once the trace is large enough, `claim_rewards` will always exceed the block gas limit and revert, permanently freezing that pool member's unclaimed yield.

---

### Finding Description

**Root cause — the unbounded loop:**

`calculate_rewards` in `src/pool/pool.cairo` (lines 837–888) contains a `while` loop that iterates over all entries in `pool_member_epoch_balance.entry(pool_member)` from `entry_to_claim_from` up to the current epoch. The developers themselves flag this:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    ...
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

Each iteration calls `find_sigma`, which performs a storage read from `cumulative_rewards_trace`, making each iteration non-trivial in gas cost.

**How the trace grows:**

Every call to `add_to_delegation_pool` (line 242) or `exit_delegation_pool_intent` (line 278) calls `increase_member_balance` / `set_member_balance`, which calls:

```cairo
trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance);
``` [2](#0-1) 

The trace's `insert` implementation appends a **new** checkpoint only when the key differs from the last entry's key. Since `get_epoch_plus_k()` returns `current_epoch + K`, and K is a fixed constant, each epoch in which a balance change occurs produces exactly one new entry:

```cairo
} else {
    // Checkpoint keys must be non-decreasing.
    assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
``` [3](#0-2) 

**How `entry_to_claim_from` fails to advance:**

`entry_to_claim_from` is stored inside `pool_member_info` and is only updated when `claim_rewards` completes successfully:

```cairo
pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
pool_member_info.reward_checkpoint = until_checkpoint;
self.write_pool_member_info(:pool_member, :pool_member_info);
``` [4](#0-3) 

If the pool member never calls `claim_rewards`, `entry_to_claim_from` stays at its initial value. The loop must then traverse every balance-change entry ever recorded for that member.

**The minimum-cost attack path:**

`add_to_delegation_pool` only requires `amount > 0`:

```cairo
assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
``` [5](#0-4) 

So a pool member can call `add_to_delegation_pool` with 1 wei once per epoch, accumulating one trace entry per epoch at negligible cost, while never calling `claim_rewards`.

---

### Impact Explanation

After N epochs of balance changes without claiming rewards, the next `claim_rewards` call must iterate over N entries, each requiring a `cumulative_rewards_trace` storage read. Once N is large enough to exhaust the block gas limit, `claim_rewards` will always revert. The pool member's accumulated yield becomes permanently unclaimable — matching the **"Permanent freezing of unclaimed yield"** impact category.

The same loop is also executed inside the view function `pool_member_info_v1` (lines 532–538), which calls `calculate_rewards` directly:

```cairo
let (rewards, _) = self
    .calculate_rewards(
        :pool_member,
        from_checkpoint: pool_member_info.reward_checkpoint,
        until_checkpoint: self.get_current_checkpoint(:pool_member),
        entry_to_claim_from: pool_member_info.entry_to_claim_from,
    );
``` [6](#0-5) 

This means even read queries for the pool member's info become uncallable once the trace is large enough.

---

### Likelihood Explanation

**Low–Medium.** The attack requires one on-chain transaction per epoch (1 wei `add_to_delegation_pool`) and zero reward claims. The cost is negligible. The number of epochs required to trigger an OOG depends on the per-iteration gas cost (each iteration reads from `cumulative_rewards_trace` storage) and the Starknet block gas limit. Given that storage reads are expensive on Starknet, a few hundred to a few thousand epochs of sustained balance changes without claiming could be sufficient. This is achievable over a realistic protocol lifetime, especially with short epoch durations.

---

### Recommendation

1. **Cap unclaimed balance-change entries**: Require `claim_rewards` before allowing more than a fixed number of balance changes since the last claim (analogous to capping denoms per delegation in the reference report).
2. **Partial-claim pattern**: Allow `claim_rewards` to process a bounded number of entries per call and store progress, so the work can be split across multiple transactions.
3. **Charge additional gas**: Impose an increasing fee for balance changes that grow the trace beyond a threshold, making the attack economically unattractive.

---

### Proof of Concept

1. Pool member `A` calls `enter_delegation_pool` with a valid amount. This initializes their `pool_member_epoch_balance` trace with one entry.
2. Each epoch, `A` calls `add_to_delegation_pool(pool_member: A, amount: 1)`. Because `get_epoch_plus_k()` returns a new key each epoch, `trace.insert` appends a new `PoolMemberBalanceCheckpoint` entry each time.
3. `A` never calls `claim_rewards`, so `pool_member_info.entry_to_claim_from` remains at its initial value.
4. After N epochs, `pool_member_epoch_balance.entry(A).length() == N + 1`.
5. Any call to `claim_rewards(pool_member: A)` now executes the `while` loop N times, each iteration reading from `cumulative_rewards_trace` storage.
6. Once N exceeds the gas-per-iteration threshold for the block gas limit, every `claim_rewards` call reverts with OOG.
7. `A`'s accumulated STRK yield is permanently frozen and unclaimable.

The relevant unbounded loop: [1](#0-0) 

The trace append path triggered by each `add_to_delegation_pool`: [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** src/pool/pool.cairo (L233-233)
```text
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
```

**File:** src/pool/pool.cairo (L241-243)
```text
            // Update the pool member's balance checkpoint.
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
            let new_delegated_stake = old_delegated_stake + amount;
```

**File:** src/pool/pool.cairo (L356-362)
```text
            rewards += pool_member_info._unclaimed_rewards_from_v0;
            pool_member_info._unclaimed_rewards_from_v0 = Zero::zero();
            pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
            pool_member_info.reward_checkpoint = until_checkpoint;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);
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
