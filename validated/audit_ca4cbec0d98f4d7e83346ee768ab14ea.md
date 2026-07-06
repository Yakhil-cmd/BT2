### Title
Unbounded `pool_member_epoch_balance` Trace Enables Permanent Freezing of Delegator Unclaimed Yield - (File: `src/pool/pool.cairo`)

---

### Summary

A pool member can grow their `pool_member_epoch_balance` trace without bound by calling `add_to_delegation_pool` (or `exit_delegation_pool_intent`) with a minimal amount once per epoch. The `calculate_rewards` function iterates over every entry in this trace without any cap. After enough epochs, the loop exceeds the Starknet block gas limit, permanently bricking the pool member's `claim_rewards` call and freezing their unclaimed yield forever.

---

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` (lines 837–888) contains an explicitly acknowledged unbounded loop:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    ...
    entry_to_claim_from += 1;
}
```

The trace it iterates over — `pool_member_epoch_balance` — is a `Vec`-backed checkpoint structure stored per pool member. Each call to `set_member_balance` (line 728) inserts a new checkpoint keyed by `get_epoch_plus_k()` (i.e., `current_epoch + K`). The `insert` logic in `trace.cairo` (lines 163–173) only **updates** the last entry if the key matches; otherwise it **appends** a new entry. Because `get_epoch_plus_k()` returns a strictly increasing value across epochs, every call to `add_to_delegation_pool` or `exit_delegation_pool_intent` in a distinct epoch appends a new checkpoint.

`add_to_delegation_pool` enforces only `amount.is_non_zero()` (line 233) — there is no minimum amount. A pool member can therefore call it with `amount = 1` once per epoch, growing the trace by one entry per epoch indefinitely.

When `claim_rewards` is eventually called (lines 340–377), it invokes `calculate_rewards` which loops over every trace entry up to the current epoch. Each iteration performs multiple storage reads (`pool_member_trace.at(...)`) and calls `find_sigma`, which itself reads from `cumulative_rewards_trace`. After enough epochs, this loop exhausts the block gas limit, causing `claim_rewards` to revert permanently.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Once the trace is large enough, `claim_rewards` will always revert with an out-of-gas error. The pool member's accrued STRK rewards become permanently inaccessible. There is no administrative escape hatch: no function exists to prune the trace or claim rewards in batches. The pool member's funds (principal) are also effectively frozen because `exit_delegation_pool_action` calls `claim_rewards` internally (or the rewards remain stuck), and the pool member cannot recover their yield.

---

### Likelihood Explanation

**Medium.** The attack requires one transaction per epoch with `amount = 1`. On Starknet, epochs are measured in blocks; a determined attacker (or even a legitimate user making many small top-ups over a long period) can reach a trace length sufficient to exceed gas limits. The cost is low: N transactions × gas + N wei of STRK. The developers themselves flagged this risk in the comment "This loop is unbounded but unlikely to exceed gas limits," acknowledging the absence of a bound.

---

### Recommendation

1. **Enforce a minimum delegation amount** in `add_to_delegation_pool` and `exit_delegation_pool_intent`, analogous to `min_stake` in the staking contract, to raise the economic cost of trace inflation.
2. **Cap the trace length** or implement a **paginated `claim_rewards`** that accepts a `max_entries` parameter, allowing partial reward claims across multiple transactions.
3. **Consolidate trace entries**: if two consecutive calls occur in the same epoch (same `get_epoch_plus_k()` key), the insert already coalesces them. Consider extending this to coalesce entries across adjacent epochs when the balance delta is negligible.

---

### Proof of Concept

**Setup:** Pool member `A` enters a delegation pool with `min_for_rewards` STRK.

**Attack loop (repeat N times, once per epoch):**
```
for epoch in 1..N:
    advance_epoch()
    pool.add_to_delegation_pool(pool_member: A, amount: 1)
    // Each call appends one new entry to pool_member_epoch_balance[A]
    // because get_epoch_plus_k() = current_epoch + K increases each epoch
```

**After N epochs:**
```
pool.claim_rewards(pool_member: A)
// Calls calculate_rewards → loops N times over pool_member_epoch_balance[A]
// Each iteration: pool_member_trace.at(i) + find_sigma (storage reads)
// At large N: exceeds Starknet block gas limit → permanent revert
```

**Relevant code path:**

`claim_rewards` → `calculate_rewards` (unbounded loop, line 859) → iterates `pool_member_epoch_balance` trace grown by `add_to_delegation_pool` → `increase_member_balance` → `set_member_balance` → `trace.insert(key: get_epoch_plus_k(), ...)` (appends new entry each epoch, line 728). [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** src/pool/pool.cairo (L221-233)
```text
        fn add_to_delegation_pool(
            ref self: ContractState, pool_member: ContractAddress, amount: Amount,
        ) -> Amount {
            // Asserts.
            self.assert_staker_is_active();
            let pool_member_info = self.internal_pool_member_info(:pool_member);
            let caller_address = get_caller_address();
            assert!(
                caller_address == pool_member || caller_address == pool_member_info.reward_address,
                "{}",
                Error::CALLER_CANNOT_ADD_TO_POOL,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
```

**File:** src/pool/pool.cairo (L346-358)
```text
            let until_checkpoint = self.get_current_checkpoint(:pool_member);

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
