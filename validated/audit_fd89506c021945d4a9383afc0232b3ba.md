### Title
Unbounded Loop in `calculate_rewards()` Can Permanently Freeze Delegator's Unclaimed Yield — (`src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards()` internal function in `src/pool/pool.cairo` contains an unbounded `while` loop that iterates over every entry in a pool member's `pool_member_epoch_balance` trace since their last checkpoint. Because the trace grows by one entry for every balance-changing action a pool member takes (delegate, partial-undelegate intent, switch pool), a delegator who accumulates a sufficiently large number of unclaimed balance-change entries will find that any subsequent call to `claim_rewards()` reverts due to exceeding the Starknet execution-resource (gas) limit. Once the trace is large enough, the delegator's accumulated yield is permanently unclaimable.

---

### Finding Description

`calculate_rewards()` is an internal function called from the public `claim_rewards()` entry point. Its core loop is:

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

The loop bound is `pool_member_trace_length`, which equals the number of entries in `self.pool_member_epoch_balance.entry(pool_member)` that fall before the current epoch. Every time a pool member performs a balance-changing operation — `enter_delegation_pool`, `exit_delegation_pool_intent`, or `switch_delegation_pool` — a new entry is appended to this trace. [2](#0-1) 

The `entry_to_claim_from` index is stored in the pool member's checkpoint and is advanced only when `claim_rewards()` succeeds. If the member never calls `claim_rewards()` between balance changes, the index stays at its old position and the next successful claim must process all accumulated entries in a single transaction. [3](#0-2) 

The developers themselves acknowledge the issue in a code comment: *"This loop is unbounded but unlikely to exceed gas limits."* [4](#0-3) 

---

### Impact Explanation

If the trace grows large enough that a single `claim_rewards()` call cannot iterate through all pending entries within the Starknet execution-resource limit, the transaction reverts. Because:

1. The trace is append-only — entries are never removed.
2. `entry_to_claim_from` is only advanced on a *successful* completion of `calculate_rewards()`.
3. There is no pagination mechanism in `claim_rewards()` that would allow partial processing.

…the delegator's unclaimed yield becomes permanently frozen. This matches the allowed impact: **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

Any unprivileged pool member (delegator) can trigger this condition by performing a large number of balance-changing operations without claiming rewards in between. The operations available to any delegator are:

- `enter_delegation_pool` (delegate more)
- `exit_delegation_pool_intent` (partial undelegate)
- `switch_delegation_pool` (move stake to another staker's pool)

Each of these appends one entry to the member's balance trace. A delegator who performs ~hundreds to low-thousands of such operations (each is a cheap on-chain transaction) without ever calling `claim_rewards()` will eventually push the trace past the gas-safe threshold. This can happen accidentally (a long-lived delegator who actively manages their position) or deliberately (a griefing attack on one's own position, or a scenario where a third party can trigger balance changes on behalf of the member through pool-switching mechanics).

---

### Recommendation

1. **Paginate `claim_rewards()`**: Accept an optional `max_entries` parameter and allow partial reward computation, storing the updated `entry_to_claim_from` in the checkpoint so subsequent calls resume where the previous one stopped.
2. **Bound balance-change frequency**: Enforce a minimum epoch gap between consecutive balance changes for the same pool member, limiting trace growth rate.
3. **Periodic forced checkpointing**: Automatically flush and consolidate the trace into a single checkpoint entry whenever `claim_rewards()` is called, so the trace never grows beyond O(1) entries per epoch.

---

### Proof of Concept

1. Alice delegates to a pool via `enter_delegation_pool`. Her `pool_member_epoch_balance` trace now has 1 entry.
2. Alice repeatedly calls `exit_delegation_pool_intent` (partial amount) followed by `switch_delegation_pool` to re-enter the same or another pool — N times — without ever calling `claim_rewards()`. Each operation appends one entry; the trace now has N+1 entries.
3. After N ≈ several hundred iterations (exact threshold depends on Starknet's per-transaction step limit and the cost of each loop body, which includes a `find_sigma` call reading from `cumulative_rewards_trace`), Alice calls `claim_rewards()`.
4. `calculate_rewards()` enters the `while` loop and attempts to iterate over all N+1 entries in a single transaction.
5. The transaction exceeds the execution-resource limit and reverts.
6. Because `entry_to_claim_from` was never advanced (the transaction reverted), every future call to `claim_rewards()` will attempt the same full iteration and revert identically.
7. Alice's accumulated yield is permanently unclaimable. [5](#0-4)

### Citations

**File:** src/pool/pool.cairo (L837-843)
```text
        fn calculate_rewards(
            self: @ContractState,
            pool_member: ContractAddress,
            from_checkpoint: PoolMemberCheckpoint,
            until_checkpoint: PoolMemberCheckpoint,
            mut entry_to_claim_from: VecIndex,
        ) -> (Amount, VecIndex) {
```

**File:** src/pool/pool.cairo (L844-851)
```text
            let pool_member_trace = self.pool_member_epoch_balance.entry(pool_member);
            // Note: `until_epoch` is the current epoch.
            let until_epoch = until_checkpoint.epoch();

            let mut rewards = 0;

            let pool_member_trace_length = pool_member_trace.length();

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
