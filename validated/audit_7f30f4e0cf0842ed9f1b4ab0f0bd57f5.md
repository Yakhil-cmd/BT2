### Title
Unbounded `pool_member_epoch_balance` Trace Loop in `calculate_rewards` Causes Permanent Freezing of Unclaimed Yield - (`src/pool/pool.cairo`)

### Summary

The `calculate_rewards` function in the Pool contract iterates over every entry in a pool member's `pool_member_epoch_balance` trace that has not yet been claimed. Because there is no cap on how many balance-change entries can accumulate, a delegator who makes many balance changes without claiming rewards will eventually be unable to claim at all: the transaction will exceed Starknet's gas limit and revert, permanently freezing their unclaimed yield.

### Finding Description

Every call to `set_member_balance` (invoked by `enter_delegation_pool`, `add_to_delegation_pool`, and `exit_delegation_pool_intent`) appends one checkpoint to the `pool_member_epoch_balance` trace for that pool member. [1](#0-0) 

When `claim_rewards` is called, it invokes `calculate_rewards`, which loops over every trace entry from `entry_to_claim_from` up to the current trace length: [2](#0-1) 

The developers themselves acknowledge the risk in a comment on line 858:

> **Note**: The loop iterates over the balance changes in the pool member's balance trace. **This loop is unbounded but unlikely to exceed gas limits.** [3](#0-2) 

Inside each loop iteration, `find_sigma` is called, which performs multiple storage reads from `cumulative_rewards_trace`: [4](#0-3) 

`find_sigma` itself reads up to three entries from the `cumulative_rewards_trace` storage vector: [5](#0-4) 

The `entry_to_claim_from` pointer is only advanced on a **successful** `claim_rewards` call: [6](#0-5) 

If the transaction reverts due to gas exhaustion, `entry_to_claim_from` is never updated, so every subsequent attempt to claim will re-encounter the same oversized loop and also revert. There is no partial-claim mechanism.

### Impact Explanation

A delegator who accumulates a sufficiently large `pool_member_epoch_balance` trace without claiming will find their `claim_rewards` call permanently reverting. Their unclaimed STRK rewards are frozen in the pool contract with no recovery path, because:

- `claim_rewards` always processes from `reward_checkpoint` to the current epoch in one shot.
- There is no function to claim a sub-range or to prune the trace.
- Once the gas limit is exceeded, every future attempt also exceeds it (the trace only grows).

This matches the **High** impact category: **Permanent freezing of unclaimed yield**.

### Likelihood Explanation

The only prerequisite is that a pool member makes many balance changes without claiming. This can happen:

1. **Naturally**: A legitimate delegator who frequently adjusts their stake (e.g., dollar-cost averaging in/out) over a long period without claiming rewards.
2. **Self-inflicted griefing**: A delegator calls `add_to_delegation_pool` with `amount = 1` (the minimum non-zero value) repeatedly. Each call costs only a token transfer of 1 unit and one storage write, making the cost to grow the trace negligible.

The only check on `add_to_delegation_pool` is `amount.is_non_zero()`: [7](#0-6) 

There is no rate-limit, minimum meaningful amount, or cap on trace length.

### Recommendation

1. **Add a cap on unclaimed balance-change entries**: Before inserting a new checkpoint in `set_member_balance`, assert that `pool_member_trace.length() - entry_to_claim_from` is below a safe maximum (e.g., 1000).
2. **Introduce partial claiming**: Allow `claim_rewards` to accept an optional `max_entries` parameter so a delegator with a large trace can drain it incrementally across multiple transactions.
3. **Enforce a minimum meaningful delegation amount**: Raise the minimum for `add_to_delegation_pool` to a value that makes trace-flooding economically infeasible.

### Proof of Concept

1. Delegator calls `enter_delegation_pool` once (trace length = 1, `entry_to_claim_from = 0`).
2. Delegator calls `add_to_delegation_pool(amount: 1)` N times without ever calling `claim_rewards`. Each call appends one entry to `pool_member_epoch_balance` (trace length = N+1).
3. After N epochs pass, delegator calls `claim_rewards`. `calculate_rewards` loops from index 0 to N, calling `find_sigma` (3 storage reads each) on every iteration.
4. For sufficiently large N, the transaction exceeds Starknet's per-transaction gas limit and reverts.
5. `entry_to_claim_from` remains 0. Every subsequent `claim_rewards` call also reverts. The delegator's accumulated STRK rewards are permanently frozen. [8](#0-7)

### Citations

**File:** src/pool/pool.cairo (L233-233)
```text
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
```

**File:** src/pool/pool.cairo (L349-362)
```text
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
            pool_member_info.reward_checkpoint = until_checkpoint;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);
```

**File:** src/pool/pool.cairo (L718-728)
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

**File:** src/pool/utils.cairo (L104-122)
```text
pub(crate) fn find_sigma_standard_case(
    cumulative_rewards_trace_vec: StorageBase<Trace>,
    cumulative_rewards_trace_idx: VecIndex,
    target_epoch: Epoch,
) -> Amount {
    // Three entries in the cumulative rewards trace are relevant (idx, idx - 1, idx - 2).
    let (epoch, sigma) = cumulative_rewards_trace_vec.at(cumulative_rewards_trace_idx);
    if epoch < target_epoch {
        return sigma;
    }
    let (epoch, sigma) = cumulative_rewards_trace_vec.at(cumulative_rewards_trace_idx - 1);
    if epoch < target_epoch {
        return sigma;
    }
    // Note: When handling a checkpoint from the old version, it never reaches here.
    let (epoch, sigma) = cumulative_rewards_trace_vec.at(cumulative_rewards_trace_idx - 2);
    assert!(epoch < target_epoch, "{}", InternalError::INVALID_EPOCH_IN_TRACE);
    sigma
}
```
