### Title
Unbounded Loop in `calculate_rewards` Can Permanently Freeze Pool Member Unclaimed Yield — (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` function in `pool.cairo` contains a `while` loop that iterates over every balance-change entry in a pool member's `pool_member_epoch_balance` trace since their last reward claim. Because there is no cap on how many entries can accumulate, a pool member who makes many balance changes across many epochs without claiming rewards will eventually be unable to claim at all — permanently freezing their unclaimed yield.

---

### Finding Description

In `src/pool/pool.cairo`, the internal function `calculate_rewards` (line 837) contains the following loop:

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

The loop iterates from `entry_to_claim_from` (the index of the first unclaimed balance-change entry) up to `pool_member_trace_length`. Every time a pool member calls `enter_delegation_pool`, `add_to_delegation_pool`, or initiates/cancels an exit intent in a new epoch, a new entry is appended to their `pool_member_epoch_balance` trace. [2](#0-1) 

The codebase itself acknowledges the risk with the comment: *"This loop is unbounded but unlikely to exceed gas limits."* There is no maximum bound enforced on the trace length, and there is no mechanism to claim rewards in partial batches (i.e., up to a caller-specified index).

---

### Impact Explanation

If a pool member accumulates a large number of balance-change entries without claiming rewards — either through normal long-term participation or deliberate repeated balance changes — any subsequent call to `claim_rewards` (or any function that internally triggers `calculate_rewards`) will iterate over all accumulated entries in a single transaction. Once the entry count is large enough, the transaction will run out of gas and revert. Because there is no partial-claim mechanism, the pool member's unclaimed yield becomes permanently inaccessible.

**Impact: High — Permanent freezing of unclaimed yield.**

---

### Likelihood Explanation

A pool member who is active over many epochs and regularly adjusts their delegation (e.g., topping up or partially withdrawing) without claiming rewards will naturally accumulate trace entries. The number of entries grows proportionally to the number of balance-change calls made across distinct epochs. On a live protocol running for months or years, this is a realistic scenario for long-term delegators. The pool member does not need any privileged access; the entry path is entirely through standard public pool member functions.

**Likelihood: Medium.**

---

### Recommendation

1. **Add a `max_entries` parameter** to the reward-claiming path so that a pool member can claim rewards for a bounded number of trace entries per transaction, storing the updated `entry_to_claim_from` checkpoint for the next call.
2. **Alternatively**, enforce a maximum number of balance-change entries per pool member per epoch (e.g., deduplicate or merge entries within the same epoch) to bound trace growth.
3. At minimum, replace the dismissive comment with a hard assertion or a documented protocol-level limit on how many epochs can pass between claims.

---

### Proof of Concept

1. Pool member calls `enter_delegation_pool` in epoch 1.
2. In each subsequent epoch, the pool member calls `add_to_delegation_pool` (or `exit_delegation_pool_intent` followed by re-entry) — adding one new entry to `pool_member_epoch_balance` per epoch — without ever calling `claim_rewards`.
3. After `N` epochs (where `N` is large enough to exhaust the block gas limit when iterating), the pool member calls `claim_rewards`.
4. `calculate_rewards` is invoked with `entry_to_claim_from = 0` and `pool_member_trace_length = N`.
5. The `while` loop at line 859 iterates `N` times, each iteration performing storage reads and arithmetic. The transaction runs out of gas and reverts.
6. Every subsequent `claim_rewards` call also reverts. The pool member's accumulated unclaimed yield is permanently frozen with no recovery path. [3](#0-2)

### Citations

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
