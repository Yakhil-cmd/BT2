### Title
Unbounded Loop in `calculate_rewards` Enables Permanent Freezing of Delegator Unclaimed Yield - (`File: src/pool/pool.cairo`)

### Summary
The `calculate_rewards` internal function in the Pool contract contains an explicitly acknowledged unbounded loop that iterates over every entry in a delegator's `pool_member_epoch_balance` trace. Because an unprivileged delegator can grow this trace without limit by repeatedly changing their delegation balance across epochs, a sufficiently large trace causes `claim_rewards` to revert with an out-of-gas error, permanently freezing the delegator's accumulated yield.

### Finding Description

The `calculate_rewards` function iterates over the entire `pool_member_epoch_balance` trace for a given pool member: [1](#0-0) 

The code comment at line 857–858 explicitly acknowledges the risk:

> **Note**: The loop iterates over the balance changes in the pool member's balance trace. This loop is unbounded but unlikely to exceed gas limits.

Each iteration also calls `find_sigma`, which in turn calls `find_sigma_standard_case` against the `cumulative_rewards_trace` vector: [2](#0-1) 

The `pool_member_epoch_balance` trace grows by one entry every time the delegator changes their balance (e.g., via `add_to_delegation_pool`, `enter_delegation_pool`, or `exit_intent`). These are all unprivileged, publicly callable operations. There is no cap on how many entries can accumulate.

The `cumulative_rewards_trace` similarly grows by one entry per epoch in which rewards are distributed. If a delegator has not claimed for many epochs, `find_sigma_standard_case` must scan a large portion of this vector for each outer-loop iteration, compounding the gas cost.

The `calculate_rewards` function is invoked from the public `claim_rewards` path: [3](#0-2) 

### Impact Explanation

Once the `pool_member_epoch_balance` trace is large enough, every call to `claim_rewards` for that delegator will revert due to gas exhaustion. The delegator's accumulated rewards become permanently inaccessible — a **permanent freezing of unclaimed yield**, which is an explicitly listed High-severity impact in the allowed scope.

### Likelihood Explanation

The trace grows by one entry per balance-change transaction. A delegator who actively manages their position (partial exits, re-entries, top-ups) across many epochs will organically accumulate a large trace. No adversarial intent is required; normal protocol usage over a long time horizon is sufficient. The protocol is designed for long-term staking, making this a realistic scenario.

### Recommendation

1. **Cap the trace length**: Enforce a maximum number of entries in `pool_member_epoch_balance` per pool member, or consolidate/prune old entries when a claim is made.
2. **Paginated claiming**: Allow `claim_rewards` to accept a `from_index` and `to_index` parameter so the caller can process the trace in bounded chunks across multiple transactions.
3. **Remove the dismissive comment**: The comment "unlikely to exceed gas limits" is not a mitigation. Replace it with a tracked issue or an enforced bound.

### Proof of Concept

1. Delegator calls `enter_delegation_pool` with a small amount in epoch 1.
2. Delegator calls `add_to_delegation_pool` with a minimal amount in each subsequent epoch for N epochs (e.g., N = 10,000). Each call appends one entry to `pool_member_epoch_balance`.
3. Delegator never calls `claim_rewards` during this period, so `cumulative_rewards_trace` also grows to length proportional to the number of epochs elapsed.
4. After N epochs, delegator calls `claim_rewards`. The `calculate_rewards` loop executes N iterations; each iteration calls `find_sigma` → `find_sigma_standard_case` over a large `cumulative_rewards_trace`.
5. The transaction runs out of gas and reverts. All accumulated rewards are permanently frozen.

The root cause is entirely within the in-scope production file `src/pool/pool.cairo`, triggered by an unprivileged delegator through standard public entry points, with no privileged access required. [4](#0-3)

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
