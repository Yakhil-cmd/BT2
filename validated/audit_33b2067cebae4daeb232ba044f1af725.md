### Title
Unbounded Loop in `calculate_rewards` Can Permanently Freeze Pool Member's Unclaimed Yield - (File: src/pool/pool.cairo)

### Summary
The `calculate_rewards` function in `pool.cairo` contains an explicitly acknowledged unbounded loop over a pool member's `pool_member_epoch_balance` trace. A delegator who makes many balance changes (add/remove delegation) across epochs can grow this trace without bound. If the trace grows large enough, their `claim_rewards` call will always revert with out-of-gas, permanently freezing their unclaimed yield.

### Finding Description
The `calculate_rewards` internal function iterates over every entry in `pool_member_epoch_balance` for a given pool member using a `while` loop. The code itself carries the comment:

> "**Note**: The loop iterates over the balance changes in the pool member's balance trace. This loop is unbounded but unlikely to exceed gas limits." [1](#0-0) 

Each time a pool member changes their delegation balance — via `add_to_delegation_pool`, `exit_intent`, `exit_action`, or `switch_delegation_pool` — a new checkpoint is appended to `pool_member_epoch_balance`. There is no cap on the number of entries. The loop runs from `entry_to_claim_from` up to `pool_member_trace_length`, iterating over every balance change since the last claim. If a pool member makes N balance changes without claiming, the loop must process all N entries in a single transaction.

Additionally, inside the loop, `find_sigma` is called on every iteration, which itself searches through the `cumulative_rewards_trace` vector: [2](#0-1) 

The `cumulative_rewards_trace` grows with every epoch that distributes rewards and is not bounded by any single user's actions. The combined cost of the outer loop and the inner `find_sigma` calls can make `claim_rewards` prohibitively expensive or impossible to execute within the block gas limit.

### Impact Explanation
If a pool member's `pool_member_epoch_balance` trace grows large enough, every subsequent call to `claim_rewards` will revert with out-of-gas. Because the trace is append-only and there is no mechanism to prune it or claim rewards in batches, the pool member's accumulated unclaimed yield becomes permanently inaccessible. This matches the allowed impact: **Permanent freezing of unclaimed yield or unclaimed royalties (High)**.

### Likelihood Explanation
Any delegator who actively manages their delegation — repeatedly adding or removing amounts across many epochs — will grow their trace. This is a normal usage pattern (e.g., a delegator who adjusts their position every few epochs over a long protocol lifetime). No malicious intent is required; the freeze can occur organically. The minimum delegation amount is a protocol parameter, so the cost to trigger this is bounded only by the number of transactions the delegator sends, not by a high token threshold. The likelihood is **Medium** for active long-term delegators.

### Recommendation
Implement a batched reward-claiming mechanism that allows a pool member to claim rewards up to a specified epoch or up to a maximum number of trace entries per transaction. Store a persistent `entry_to_claim_from` cursor in the pool member's state so that multiple partial claims can be made across separate transactions, analogous to the batched-refund recommendation in the reference report.

### Proof of Concept
1. Delegator calls `add_to_delegation_pool` with a small amount, then `exit_intent` + `exit_action`, repeatedly across many epochs. Each cycle appends two entries to `pool_member_epoch_balance`.
2. After N cycles (e.g., N = 500–1000 depending on Starknet's step budget), the trace has 2N entries.
3. Delegator calls `claim_rewards`. The `calculate_rewards` loop must iterate over all 2N entries, calling `find_sigma` on each iteration.
4. The transaction exceeds the block gas/steps limit and reverts.
5. Every future `claim_rewards` call for this pool member also reverts, because the trace only grows and is never pruned.
6. The pool member's accumulated unclaimed yield is permanently frozen with no recovery path. [3](#0-2)

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
