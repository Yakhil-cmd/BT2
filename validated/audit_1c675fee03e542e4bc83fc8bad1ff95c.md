### Title
Unbounded Loop in `calculate_rewards` Can Permanently Freeze Pool Member's Unclaimed Yield - (File: src/pool/pool.cairo)

### Summary
The `calculate_rewards` internal function in `src/pool/pool.cairo` contains an unbounded `while` loop that iterates over every entry in a pool member's `pool_member_epoch_balance` trace since their last claim. A pool member who makes frequent balance changes across many epochs without claiming will accumulate a large trace. When they eventually call `claim_rewards`, the loop can exhaust the Starknet transaction gas limit, permanently preventing them from ever claiming their accrued yield.

### Finding Description

The loop at `src/pool/pool.cairo:859–877` is explicitly acknowledged by the developers as unbounded:

```
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    ...
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

The `pool_member_epoch_balance` trace grows by one entry every time a pool member changes their delegated balance in a new epoch (e.g., via `add_to_delegation_pool` or `exit_delegation_pool_intent`). The loop iterates from the stored `entry_to_claim_from` index (set at the last successful claim) up to the current trace length, processing every balance-change checkpoint that falls before the current epoch. [2](#0-1) 

If a pool member makes one balance change per epoch across N epochs without ever calling `claim_rewards`, the trace accumulates N entries. The next `claim_rewards` call must iterate all N entries in a single transaction. There is no partial-claim mechanism or batch-size parameter exposed in the interface to limit the iteration range.

### Impact Explanation

**Severity: High — Permanent freezing of unclaimed yield.**

Once the trace is large enough that a single `claim_rewards` transaction exceeds the Starknet gas limit, the pool member's accumulated rewards become permanently inaccessible. There is no alternative code path to claim rewards in smaller batches. The pool member loses all yield earned since their last claim (or since joining the pool if they never claimed). [3](#0-2) 

### Likelihood Explanation

**Likelihood: Medium.**

A pool member who actively manages their delegation position — adding or removing stake once per epoch — will accumulate one trace entry per epoch. Starknet epochs are short (roughly one block interval in the pre-consensus phase). A moderately active delegator who goes several hundred epochs without claiming (e.g., due to high gas prices, inattention, or a front-end outage) can reach a trace length that causes OOG. The developers themselves flag this risk in the comment at line 858. [4](#0-3) 

### Recommendation

1. **Checkpoint-based partial claiming**: Expose a `claim_rewards_up_to(epoch: Epoch)` entry point that processes only a bounded slice of the trace per transaction, storing the updated `entry_to_claim_from` so subsequent calls continue from where the previous one stopped.
2. **Limit trace growth**: Enforce a maximum number of balance-change entries per pool member per epoch (e.g., collapse multiple changes within the same epoch into a single checkpoint), preventing unbounded trace accumulation.
3. **Batch-size cap**: Add a `max_iterations` guard inside `calculate_rewards` that returns a partial result and a continuation cursor, allowing callers to resume in a subsequent transaction.

### Proof of Concept

1. Pool member `Alice` joins a pool and makes one `add_to_delegation_pool` call per epoch for 10,000 epochs without ever calling `claim_rewards`. Each call in a new epoch appends one entry to `pool_member_epoch_balance` for `Alice`.
2. After 10,000 epochs, `Alice` calls `claim_rewards`.
3. `calculate_rewards` is invoked with `entry_to_claim_from = 0` and `pool_member_trace_length = 10,000`.
4. The `while` loop at line 859 iterates up to 10,000 times, each iteration reading a storage slot and calling `find_sigma`.
5. The transaction exceeds the Starknet gas limit and reverts.
6. Every subsequent `claim_rewards` call by `Alice` also reverts — her yield is permanently frozen. [5](#0-4)

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
