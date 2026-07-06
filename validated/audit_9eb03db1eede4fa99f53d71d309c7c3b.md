### Title
Unbounded Loop in `calculate_rewards` Can Permanently Freeze Unclaimed Yield - (File: src/pool/pool.cairo)

### Summary
The `calculate_rewards` function in `pool.cairo` contains an explicitly acknowledged unbounded loop that iterates over a pool member's entire `pool_member_epoch_balance` trace. A pool member who makes many balance changes across many epochs without claiming rewards will grow this trace without bound. Eventually, a `claim_rewards` call will iterate over so many entries that it exhausts the transaction gas limit and reverts, permanently freezing the pool member's unclaimed yield.

### Finding Description
In `pool.cairo`, the internal `calculate_rewards` function iterates over every entry in `pool_member_epoch_balance` for a given pool member, from `entry_to_claim_from` up to the current epoch: [1](#0-0) 

The code comment at line 857–858 explicitly acknowledges the risk:

> **Note**: The loop iterates over the balance changes in the pool member's balance trace. This loop is unbounded but unlikely to exceed gas limits.

Each call to `delegate`, `increase_delegate`, or `exit_intent` by a pool member appends a new entry to their `pool_member_epoch_balance` trace. If a pool member makes one balance change per epoch and never claims, after `N` epochs the loop must process `N` entries on the next claim. On StarkNet, transactions have a finite gas/step budget; once `N` is large enough, the `claim_rewards` transaction will always revert.

The `entry_to_claim_from` cursor is stored in the pool member's checkpoint and is only advanced when a successful claim completes. Because the claim itself reverts, the cursor never advances, making the freeze permanent. [2](#0-1) 

### Impact Explanation
Once the trace is large enough, every future `claim_rewards` call for that pool member reverts. The pool member's accumulated yield is permanently locked in the pool contract with no recovery path, because the only way to advance `entry_to_claim_from` is through a successful `claim_rewards` execution, which is now impossible.

This matches the allowed impact: **Permanent freezing of unclaimed yield** (High).

### Likelihood Explanation
Any pool member who:
1. Makes frequent balance changes (delegate/increase/exit-intent) across many epochs, **and**
2. Defers claiming rewards for a long time

will eventually hit this condition. The protocol is designed to run indefinitely; over a sufficiently long time horizon, active delegators who adjust their positions regularly will accumulate large traces. The developers themselves flag this as a known risk ("unbounded but unlikely"), confirming the path exists.

### Recommendation
Introduce a pagination mechanism analogous to the BondAggregator fix: accept a `max_entries` or `until_entry_index` parameter in `claim_rewards` / `calculate_rewards` so a pool member can claim rewards in batches, advancing `entry_to_claim_from` incrementally across multiple transactions rather than requiring a single unbounded pass.

### Proof of Concept
1. Pool member `A` delegates to a pool at epoch 0.
2. Every epoch, `A` calls `increase_delegate` (or `exit_intent` + re-delegate), appending one entry to `pool_member_epoch_balance[A]`.
3. `A` never calls `claim_rewards`.
4. After `N` epochs (where `N` is large enough to exhaust the step budget), `A` calls `claim_rewards`.
5. `calculate_rewards` enters the `while entry_to_claim_from < pool_member_trace_length` loop and iterates `N` times, each iteration reading storage and calling `find_sigma`.
6. The transaction runs out of gas and reverts.
7. `entry_to_claim_from` in `A`'s checkpoint is never updated; every subsequent `claim_rewards` call also reverts.
8. `A`'s unclaimed yield is permanently frozen. [3](#0-2)

### Citations

**File:** src/pool/pool.cairo (L843-888)
```text
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
