### Title
Unbounded Loop Over Growing `pool_member_epoch_balance` Trace Causes Permanent DoS of `claim_rewards` - (File: src/pool/pool.cairo)

### Summary

The `calculate_rewards` function in `src/pool/pool.cairo` iterates over a pool member's `pool_member_epoch_balance` trace in an unbounded loop. This trace grows by one checkpoint per epoch whenever a pool member modifies their balance. If a pool member accumulates many balance-change epochs without claiming rewards, the loop can eventually exceed Starknet's gas limits, permanently freezing their unclaimed yield. The code itself acknowledges this: *"This loop is unbounded but unlikely to exceed gas limits."*

### Finding Description

**Root cause — growing trace, never pruned:**

`pool_member_epoch_balance` is a `Map<ContractAddress, PoolMemberBalanceTrace>` (a `Vec`-backed checkpoint list). Every call to `set_member_balance` or `increase_member_balance` inserts a new checkpoint keyed at `current_epoch + K`:

```cairo
// src/pool/pool.cairo line 728
trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance);
```

The `insert` logic in `src/pool/pool_member_balance_trace/trace.cairo` (lines 152–175) only deduplicates within the *same* epoch key; a different epoch always appends a new entry. The trace is never pruned or compacted.

**Unbounded loop in `calculate_rewards`:**

`calculate_rewards` (lines 837–888) iterates from the stored `entry_to_claim_from` index to the current trace length:

```cairo
// src/pool/pool.cairo lines 857–877
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch { break; }
    let to_sigma = self.find_sigma(pool_member_checkpoint, curr_epoch: until_epoch);
    ...
    entry_to_claim_from += 1;
}
```

Inside each iteration, `find_sigma` (lines 897–933) performs an additional lookup into `cumulative_rewards_trace`, which itself grows monotonically (one entry per epoch of rewards). This makes the per-iteration cost non-trivial and the total cost potentially O(N × M) where N = unclaimed balance-change epochs and M = cumulative rewards trace length.

**`entry_to_claim_from` is only advanced by `claim_rewards`:**

`claim_rewards` (lines 335–377) updates `entry_to_claim_from` after a successful call. If the pool member never calls `claim_rewards` while repeatedly modifying their balance across epochs, the gap between `entry_to_claim_from` and the current trace length grows without bound. The view function `pool_member_info_v1` (lines 528–548) also calls `calculate_rewards` without advancing `entry_to_claim_from`, so it provides no relief.

**Attacker-controlled entry path:**

A pool member (unprivileged) can:
1. Call `add_to_delegation_pool` (line 221) or `exit_delegation_pool_intent` + re-enter once per epoch to append one checkpoint per epoch.
2. Deliberately withhold calls to `claim_rewards`.
3. After N epochs, the trace has N unprocessed entries. The next `claim_rewards` call must iterate all N entries (each invoking `find_sigma` over a growing `cumulative_rewards_trace`).

This can also happen non-maliciously: a long-term delegator who changes their stake frequently but claims infrequently will naturally accumulate a large trace.

### Impact Explanation

When the trace grows large enough, `claim_rewards` will always revert with an out-of-gas error. Because `entry_to_claim_from` is only advanced inside `claim_rewards`, and `claim_rewards` is the only way to advance it, the pool member's unclaimed yield becomes permanently frozen — there is no administrative escape hatch or batch-claim mechanism to process the trace in smaller chunks.

**Impact: High — Permanent freezing of unclaimed yield.**

### Likelihood Explanation

- Any pool member who changes their balance across many epochs without claiming rewards is at risk.
- The minimum delegation amount (`min_for_rewards = 10^18` STRK, i.e., 1 STRK) is low enough that this is reachable by ordinary delegators.
- The growth rate is one checkpoint per epoch per balance change; over hundreds of epochs (a realistic multi-year horizon), the trace can reach sizes that cause gas exhaustion, especially given the nested `find_sigma` cost.
- The code comment explicitly acknowledges the loop is unbounded, confirming the developers are aware of the risk but have not mitigated it.

**Likelihood: Medium** — requires sustained balance changes without reward claims, but is reachable by any unprivileged pool member over a long enough time horizon.

### Recommendation

1. **Paginated claiming**: Add a `claim_rewards_partial(pool_member, max_entries)` function that advances `entry_to_claim_from` by at most `max_entries` per call, allowing the pool member to drain the trace over multiple transactions.
2. **Checkpoint compaction**: When `claim_rewards` is called, compact processed entries (or record a high-water mark) so the next call does not re-scan already-processed checkpoints. The current `entry_to_claim_from` mechanism already does this correctly — the issue is that a single call must process all accumulated entries at once.
3. **Enforce periodic claiming**: Require or incentivize pool members to claim rewards at least once every N epochs, preventing unbounded accumulation.

### Proof of Concept

1. Pool member calls `enter_delegation_pool` to join the pool.
2. For each of N epochs, pool member calls `add_to_delegation_pool` with a dust amount (1 wei). Each call appends one checkpoint to `pool_member_epoch_balance` via `set_member_balance` → `trace.insert(key: current_epoch + K, ...)`.
3. Pool member never calls `claim_rewards`, so `entry_to_claim_from` remains at 0.
4. After N epochs, `pool_member_epoch_balance` has N entries.
5. Pool member calls `claim_rewards`. `calculate_rewards` enters the `while` loop and iterates all N entries, calling `find_sigma` (which reads `cumulative_rewards_trace`) on each iteration.
6. For sufficiently large N, the transaction runs out of gas and reverts.
7. Because `entry_to_claim_from` was never advanced (the call always reverts), all subsequent `claim_rewards` calls also revert. The pool member's accumulated yield is permanently frozen.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** src/pool/pool.cairo (L335-377)
```text
        fn claim_rewards(ref self: ContractState, pool_member: ContractAddress) -> Amount {
            // Asserts.
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let caller_address = get_caller_address();
            let reward_address = pool_member_info.reward_address;
            assert!(
                caller_address == pool_member || caller_address == reward_address,
                "{}",
                Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );

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
            pool_member_info.reward_checkpoint = until_checkpoint;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());

            // Emit event.
            self
                .emit(
                    Events::PoolMemberRewardClaimed {
                        pool_member, reward_address, amount: rewards,
                    },
                );

            rewards
        }
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

**File:** src/pool/pool.cairo (L897-933)
```text
        fn find_sigma(
            self: @ContractState, pool_member_checkpoint: PoolMemberCheckpoint, curr_epoch: Epoch,
        ) -> Amount {
            let pool_member_checkpoint_epoch = pool_member_checkpoint.epoch();
            assert!(
                pool_member_checkpoint_epoch <= curr_epoch,
                "{}",
                InternalError::INVALID_EPOCH_IN_TRACE,
            );
            let cumulative_rewards_trace_vec = self.cumulative_rewards_trace;
            let cumulative_rewards_trace_idx = pool_member_checkpoint
                .cumulative_rewards_trace_idx();

            // **Reminder**:
            // Let `len` be the length of `cumulative_rewards_trace_vec` at the time the checkpoint
            // is written.
            // In old version: `cumulative_rewards_trace_idx` = `len`.
            // In this version: `cumulative_rewards_trace_idx` = `len + 1`.
            // For current checkpoint in both versions: `cumulative_rewards_trace_idx` = `len - 1`.
            // **Invariant**:
            // 1. `cumulative_rewards_trace_vec.length() >= 1`.
            // 2. `cumulative_rewards_trace_vec.length()` is only increased, never decreased.
            if let Some(sigma) =
                find_sigma_edge_cases(
                    :cumulative_rewards_trace_vec,
                    :cumulative_rewards_trace_idx,
                    target_epoch: pool_member_checkpoint_epoch,
                ) {
                return sigma;
            }

            find_sigma_standard_case(
                :cumulative_rewards_trace_vec,
                :cumulative_rewards_trace_idx,
                target_epoch: pool_member_checkpoint_epoch,
            )
        }
```

**File:** src/pool/pool_member_balance_trace/trace.cairo (L152-175)
```text
    fn insert(
        self: StoragePath<Mutable<PoolMemberBalanceTrace>>, key: Epoch, value: PoolMemberBalance,
    ) -> (PoolMemberBalance, PoolMemberBalance) {
        let checkpoints = self.checkpoints;

        let len = checkpoints.len();
        if len == Zero::zero() {
            checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
            return (Zero::zero(), value);
        }

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
        (prev, value)
    }
```
