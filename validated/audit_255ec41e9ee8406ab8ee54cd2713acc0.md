### Title
Unbounded Loop Over `pool_member_epoch_balance` Trace in `calculate_rewards` Can Permanently Freeze Delegator's Unclaimed Yield - (File: src/pool/pool.cairo)

### Summary
The `calculate_rewards` function in `src/pool/pool.cairo` contains an explicitly acknowledged unbounded loop that iterates over a delegator's entire `pool_member_epoch_balance` trace. Because every call to `add_to_delegation_pool` or `exit_delegation_pool_intent` appends a new entry to this trace (one per epoch), a delegator who accumulates many balance-change epochs without claiming rewards will eventually cause `claim_rewards` to exceed the Starknet transaction gas limit, permanently freezing their unclaimed yield.

### Finding Description

`calculate_rewards` (pool.cairo:837–888) iterates over every entry in `pool_member_epoch_balance` that falls between the delegator's last reward checkpoint and the current epoch:

```
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch { break; }
    let to_sigma = self.find_sigma(pool_member_checkpoint, curr_epoch: until_epoch);
    rewards += compute_rewards_rounded_down(...);
    ...
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

Each call to `add_to_delegation_pool` invokes `increase_member_balance` → `set_member_balance`, which calls `trace.insert(key: self.get_epoch_plus_k(), ...)`. Because `get_epoch_plus_k()` returns `current_epoch + K`, a call in epoch N inserts at epoch N+2. A call in epoch N+1 inserts at epoch N+3 — a distinct key — so the trace grows by one entry per epoch of balance change. [2](#0-1) [3](#0-2) 

Similarly, `exit_delegation_pool_intent` calls `set_member_balance` unconditionally (including when `amount == 0`), adding another trace entry each epoch it is called. [4](#0-3) 

The `entry_to_claim_from` cursor is only advanced and saved when `claim_rewards` succeeds. If the delegator never claims (or claims are blocked), the loop must re-traverse the entire accumulated trace from the last saved checkpoint on every future `claim_rewards` call. [5](#0-4) 

The codebase itself acknowledges the risk with the comment: *"This loop is unbounded but unlikely to exceed gas limits."* [6](#0-5) 

### Impact Explanation

Once the trace is large enough that a single `claim_rewards` call exhausts the Starknet transaction gas limit, the delegator's rewards are **permanently frozen**: every future `claim_rewards` call will revert with OOG, and there is no partial-claim or pagination mechanism to recover. This matches the **High** impact category: *Permanent freezing of unclaimed yield*.

### Likelihood Explanation

Each epoch adds at most one new trace entry (the `insert` function overwrites if the key already exists within the same epoch). [7](#0-6) 

The number of epochs required to reach the gas limit depends on Starknet's per-transaction gas cap and the per-iteration cost (one storage read in `pool_member_trace.at`, plus `find_sigma` which reads `cumulative_rewards_trace`). At realistic epoch lengths (days to weeks), accumulating a trace large enough to cause OOG would take years of deliberate non-claiming combined with per-epoch balance changes. Likelihood is therefore **low** for an organic user but non-zero for a griefing scenario where an attacker controls the `reward_address` of a pool member and repeatedly calls `add_to_delegation_pool` on their behalf each epoch (the function permits the reward address as caller). [8](#0-7) 

### Recommendation

1. **Paginate `calculate_rewards`**: Accept a `max_iterations` parameter and return a partial result with an updated `entry_to_claim_from`, allowing the delegator to call `claim_rewards` multiple times to drain a large trace incrementally.
2. **Enforce periodic claiming**: Require that `entry_to_claim_from` is not too far behind the current trace length before allowing further balance changes, analogous to capping the notification list in the reference report.
3. **Compact the trace on claim**: After advancing `entry_to_claim_from`, truncate or compact already-processed entries so the trace does not grow without bound.

### Proof of Concept

1. Delegator calls `enter_delegation_pool` with the minimum amount.
2. Each epoch, delegator calls `add_to_delegation_pool` with 1 wei (or `exit_delegation_pool_intent(0)`). Each call appends one entry to `pool_member_epoch_balance` at `current_epoch + K`.
3. Delegator never calls `claim_rewards`, so `entry_to_claim_from` stays at 0.
4. After N epochs, `pool_member_epoch_balance` has N entries.
5. Delegator calls `claim_rewards`. `calculate_rewards` enters the `while` loop and iterates N times, each iteration reading from storage and calling `find_sigma`. For sufficiently large N, the transaction reverts with OOG.
6. All subsequent `claim_rewards` calls also revert. The delegator's accumulated yield is permanently inaccessible.

### Citations

**File:** src/pool/pool.cairo (L227-232)
```text
            let caller_address = get_caller_address();
            assert!(
                caller_address == pool_member || caller_address == pool_member_info.reward_address,
                "{}",
                Error::CALLER_CANNOT_ADD_TO_POOL,
            );
```

**File:** src/pool/pool.cairo (L241-243)
```text
            // Update the pool member's balance checkpoint.
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
            let new_delegated_stake = old_delegated_stake + amount;
```

**File:** src/pool/pool.cairo (L277-278)
```text
            // Update the pool member's balance checkpoint.
            self.set_member_balance(:pool_member, amount: new_delegated_stake);
```

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
