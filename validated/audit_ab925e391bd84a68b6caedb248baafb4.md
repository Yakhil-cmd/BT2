### Title
Unbounded Loop in `calculate_rewards` Over Pool Member Balance Trace Can Permanently Freeze Unclaimed Yield - (File: `src/pool/pool.cairo`)

### Summary
The `calculate_rewards` function in the Pool contract iterates over every entry in a pool member's `pool_member_epoch_balance` trace since their last claim. Because there is no cap on how many entries this trace can accumulate, a pool member who repeatedly changes their delegation balance across different epochs without claiming rewards will grow the trace unboundedly. When the trace is large enough, `claim_rewards` (and `pool_member_info_v1`) will run out of gas, permanently freezing the pool member's unclaimed yield.

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` contains an explicitly acknowledged unbounded loop:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
``` [1](#0-0) 

The loop iterates from `entry_to_claim_from` (the index saved at the last successful claim) to the current end of the `pool_member_epoch_balance` trace. Each call to `set_member_balance` inserts a new checkpoint at `current_epoch + K`:

```cairo
trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance);
``` [2](#0-1) 

The underlying `insert` implementation only deduplicates entries with the **same** epoch key; entries with distinct epoch keys are always appended as new checkpoints:

```cairo
} else {
    // Checkpoint keys must be non-decreasing.
    assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
``` [3](#0-2) 

There is **no cap** on the length of this trace. Every call to `add_to_delegation_pool` or `exit_delegation_pool_intent` in a new epoch appends a distinct entry. Both functions call `increase_member_balance` / `set_member_balance`: [4](#0-3) [5](#0-4) 

`calculate_rewards` is called by two public entry points:

1. `claim_rewards` — a state-changing function that transfers rewards to the pool member.
2. `pool_member_info_v1` — a view function that computes pending rewards. [6](#0-5) [7](#0-6) 

### Impact Explanation

If a pool member accumulates enough balance-change entries between two consecutive claims, the `calculate_rewards` loop will consume more gas than the Starknet transaction gas limit allows. The transaction reverts, and because `entry_to_claim_from` is only updated on a **successful** claim, every subsequent attempt to call `claim_rewards` will retry the same oversized loop and revert again. The pool member's accrued rewards are permanently inaccessible — a **permanent freezing of unclaimed yield**.

### Likelihood Explanation

The scenario requires no privileged access and no adversarial third party. A pool member who routinely adjusts their delegation (e.g., dollar-cost averaging in or out) across many epochs without periodically claiming rewards will organically grow their trace. The protocol imposes no maximum on the number of balance changes, and the code comment itself concedes the loop is unbounded. The risk scales with the number of epochs a pool member is active and the frequency of their balance changes.

### Recommendation

1. **Enforce a cap** on the number of unclaimed balance-change entries per pool member, analogous to the `MAX_STAKING_CONDITIONS_LIMIT` introduced in the referenced fix. Reject or consolidate new balance changes once the cap is reached.
2. **Alternatively**, add a `claim_rewards_partial(pool_member, max_entries)` function that lets a pool member process a bounded number of trace entries per transaction, giving them control over gas usage and a path to recover from a bloated trace.
3. **At minimum**, document the maximum safe trace length based on Starknet's gas limits and enforce it on-chain.

### Proof of Concept

1. Pool member calls `enter_delegation_pool` to join the pool.
2. For each epoch `i` from 1 to N (where N is large enough to exhaust gas), the pool member calls `add_to_delegation_pool` with a small amount. Each call in a new epoch appends a new entry to `pool_member_epoch_balance` at epoch `i + K`.
3. The pool member never calls `claim_rewards`, so `entry_to_claim_from` remains at 0.
4. After N epochs, the pool member calls `claim_rewards`. The `calculate_rewards` loop must iterate over all N entries. For sufficiently large N, the transaction runs out of gas and reverts.
5. Every subsequent call to `claim_rewards` faces the same N-entry loop and reverts. The pool member's accumulated yield is permanently frozen.

The exact value of N at which gas exhaustion occurs depends on Starknet's per-transaction gas limit and the cost of each loop iteration (one storage read of `pool_member_epoch_balance` plus one call to `find_sigma`), but the absence of any on-chain cap means N is unbounded by protocol design. [8](#0-7)

### Citations

**File:** src/pool/pool.cairo (L241-243)
```text
            // Update the pool member's balance checkpoint.
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
            let new_delegated_stake = old_delegated_stake + amount;
```

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

**File:** src/pool/pool.cairo (L721-729)
```text
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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L169-173)
```text
        } else {
            // Checkpoint keys must be non-decreasing.
            assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
            checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
        }
```
