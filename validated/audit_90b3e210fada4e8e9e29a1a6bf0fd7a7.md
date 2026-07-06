### Title
Unbounded Loop with Repeated Storage Reads in `calculate_rewards` Can Permanently Freeze Delegator's Unclaimed Yield - (File: src/pool/pool.cairo)

### Summary
`Pool.calculate_rewards` contains an unbounded `while` loop that iterates over every balance-change checkpoint a pool member has accumulated since their last claim. Each iteration calls `find_sigma`, which performs up to 3–4 storage reads from `cumulative_rewards_trace`. A delegator who changes their balance every epoch without claiming will grow their `pool_member_epoch_balance` trace without bound, eventually making `claim_rewards` (and `pool_member_info_v1`) exceed Starknet's gas ceiling and permanently freeze their unclaimed yield.

### Finding Description

`Pool.calculate_rewards` (called by both `claim_rewards` and `pool_member_info_v1`) iterates over every entry in the caller's `pool_member_epoch_balance` trace that falls between `entry_to_claim_from` and the current epoch: [1](#0-0) 

The code itself acknowledges the risk with the comment:

> **Note**: The loop iterates over the balance changes in the pool member's balance trace. This loop is unbounded but unlikely to exceed gas limits.

Inside every iteration, `find_sigma` is called: [2](#0-1) 

`find_sigma` dispatches to either `find_sigma_edge_cases` or `find_sigma_standard_case`. The standard case reads up to **3 storage slots** from `cumulative_rewards_trace_vec`: [3](#0-2) 

Additionally, each iteration reads one storage slot via `pool_member_trace.at(entry_to_claim_from)`: [4](#0-3) 

So each loop iteration costs **4–5 storage reads**. After the loop, `find_sigma` is called once more for `until_checkpoint`: [5](#0-4) 

The trace grows by at most one entry per epoch (the `insert` function deduplicates within the same epoch key): [6](#0-5) 

The `entry_to_claim_from` cursor is only advanced when `claim_rewards` is successfully executed: [7](#0-6) 

A delegator who changes their balance every epoch but never claims will accumulate one new checkpoint per epoch. After N epochs without claiming, `calculate_rewards` must iterate N times with 4–5 storage reads each.

### Impact Explanation

If the accumulated trace is large enough that `claim_rewards` exceeds Starknet's gas limit, the delegator's unclaimed yield is **permanently frozen**: every future call to `claim_rewards` will also fail (the cursor never advances past the gas-exhausting entries), and the rewards can never be transferred to the reward address.

This matches the allowed impact: **Permanent freezing of unclaimed yield**.

### Likelihood Explanation

A delegator who:
1. Joins a pool and changes their delegated amount (via `add_to_delegation_pool` or `exit_delegation_pool_intent`) once per epoch, and
2. Does not call `claim_rewards` for an extended period

will grow their trace linearly with time. The delegator controls both actions. No privileged role or external dependency is required. The scenario is realistic for long-term participants who accumulate many small balance adjustments (e.g., compounding strategies, automated rebalancers) without regularly claiming.

### Recommendation

1. **Cap the number of loop iterations per call** by processing only a bounded window of checkpoints per `claim_rewards` invocation and storing the updated `entry_to_claim_from` cursor so subsequent calls resume where the previous one stopped. This is already partially implemented via `entry_to_claim_from` — the missing piece is a per-call iteration limit.
2. **Document and enforce a maximum trace length** or add a protocol-level cap on how many balance-change checkpoints a single pool member may accumulate without claiming.
3. Consider **merging consecutive checkpoints** when a delegator claims, so the trace never grows unboundedly.

### Proof of Concept

1. Delegator calls `enter_delegation_pool` at epoch 0.
2. For each epoch `i` from 1 to N (e.g., N = 10,000), the delegator calls `add_to_delegation_pool` with a small amount. Each call inserts a new checkpoint at epoch `i + K` via `set_member_balance` → `pool_member_epoch_balance.insert`.
3. The delegator never calls `claim_rewards`, so `entry_to_claim_from` remains at 0.
4. At epoch N, the delegator calls `claim_rewards`. `calculate_rewards` enters the `while` loop with `pool_member_trace_length ≈ N`. Each of the N iterations calls `find_sigma` (3–4 storage reads) plus one `pool_member_trace.at` read ≈ 4–5 reads/iteration → ~40,000–50,000 storage reads total.
5. The transaction runs out of gas. `entry_to_claim_from` is never updated (the transaction reverts). Every subsequent `claim_rewards` call also reverts. The delegator's accumulated yield is permanently inaccessible. [8](#0-7) [9](#0-8)

### Citations

**File:** src/pool/pool.cairo (L348-359)
```text
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
            pool_member_info.reward_checkpoint = until_checkpoint;
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

**File:** src/pool/utils.cairo (L34-122)
```text
pub(crate) fn find_sigma_edge_cases(
    cumulative_rewards_trace_vec: StorageBase<Trace>,
    cumulative_rewards_trace_idx: VecIndex,
    target_epoch: Epoch,
) -> Option<Amount> {
    // Edge case 1: Pool member enter delegation before any rewards given to the pool.
    if cumulative_rewards_trace_idx == 0 {
        return Some(Zero::zero());
    }

    let cumulative_rewards_trace_len = cumulative_rewards_trace_vec.length();

    // Edge case 2: `idx = len`.
    // In this version: `len + 1` was written, and rewards given to pool from that moment
    // only once.
    // In old version: `len` was written, and no rewards given to pool from that moment.
    if cumulative_rewards_trace_idx == cumulative_rewards_trace_len {
        // Two entries in the cumulative rewards trace are relevant (`idx - 1`, `idx - 2`).
        let (epoch, sigma) = cumulative_rewards_trace_vec.at(cumulative_rewards_trace_idx - 1);
        // In case `idx == 1`, `(epoch, sigma)` at `idx - 1` is `(0,0)` (the first trace
        // entry), so always return here.
        // This case only occurs in old-version checkpoints. In the current version, `idx =
        // 1` implies `len - 1` was written, so `len > idx` and we never reach this point.
        if epoch < target_epoch {
            return Some(sigma);
        }
        // Note: When handling a checkpoint from the old version, it never reaches here.
        assert!(cumulative_rewards_trace_idx > 1, "{}", InternalError::INVALID_REWARDS_TRACE_IDX);
        let (epoch, sigma) = cumulative_rewards_trace_vec.at(cumulative_rewards_trace_idx - 2);
        assert!(epoch < target_epoch, "{}", InternalError::INVALID_EPOCH_IN_TRACE);
        return Some(sigma);
    }

    // Edge case 3: `idx = 1`.
    // In this version: `len - 1` was written for the current checkpoint. (`len + 1` wasn't
    // written since `len >= 1`).
    // In old version: `len` was written, or `len - 1` was written for the current
    // checkpoint.
    // TODO: Use helper function that gets index and looks at two entries in the cumulative
    // rewards trace here and in edge case 2.
    if cumulative_rewards_trace_idx == 1 && cumulative_rewards_trace_len > 1 {
        // Two entries in the cumulative rewards trace are relevant (`idx`, `idx - 1`).
        let (epoch, sigma) = cumulative_rewards_trace_vec.at(cumulative_rewards_trace_idx);
        if epoch < target_epoch {
            return Some(sigma);
        }
        let (epoch, sigma) = cumulative_rewards_trace_vec.at(cumulative_rewards_trace_idx - 1);
        assert!(epoch < target_epoch, "{}", InternalError::INVALID_EPOCH_IN_TRACE);
        return Some(sigma);
    }

    // Edge case 4: `idx = len + 1`.
    // In this version: `len + 1` was written, and no rewards given to pool from that
    // moment.
    // In old version: never reached here (`len` or `len - 1` was written).
    if cumulative_rewards_trace_idx == cumulative_rewards_trace_len + 1 {
        // Only one entry in the cumulative rewards trace is relevant (`idx - 2`).
        let (epoch, sigma) = cumulative_rewards_trace_vec.at(cumulative_rewards_trace_len - 1);
        assert!(epoch < target_epoch, "{}", InternalError::INVALID_EPOCH_IN_TRACE);
        return Some(sigma);
    }

    None
}

/// Returns the sigma for the standard case of `find_sigma`.
/// Looks at up to 3 checkpoints in `cumulative_rewards_trace_vec`,
/// `cumulative_rewards_trace_idx`, `cumulative_rewards_trace_idx - 1` and
/// `cumulative_rewards_trace_idx - 2`, and takes the latest one (among these checkpoints)
/// whose `epoch` < `target_epoch`.
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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L135-145)
```text
    fn at(self: StoragePath<PoolMemberBalanceTrace>, pos: VecIndex) -> PoolMemberCheckpoint {
        let checkpoints = self.checkpoints;
        let len = checkpoints.len();
        assert!(pos < len, "{}", TraceErrors::INDEX_OUT_OF_BOUNDS);
        let checkpoint = checkpoints[pos].read();
        PoolMemberCheckpointTrait::new(
            epoch: checkpoint.key,
            balance: checkpoint.value.balance,
            cumulative_rewards_trace_idx: checkpoint.value.cumulative_rewards_trace_idx,
        )
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
