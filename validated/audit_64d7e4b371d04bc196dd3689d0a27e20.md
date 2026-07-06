### Title
Unbounded Loop in `calculate_rewards` Can Permanently Freeze Pool Member's Unclaimed Yield - (File: `src/pool/pool.cairo`)

### Summary
The `calculate_rewards` function in the Pool contract contains an explicitly acknowledged unbounded loop that iterates over every balance-change checkpoint in a pool member's trace since their last reward claim. A pool member who accumulates many balance-change epochs without claiming rewards can reach a state where their `claim_rewards` transaction permanently exceeds the Starknet block gas limit, irreversibly freezing their unclaimed yield.

### Finding Description
In `src/pool/pool.cairo`, the internal `calculate_rewards` function iterates over the `pool_member_epoch_balance` trace:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch {
        break;
    }
    let to_sigma = self.find_sigma(pool_member_checkpoint, curr_epoch: until_epoch);
    ...
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

The loop bound is `pool_member_trace_length`, which is the length of the `PoolMemberBalanceTrace` stored per pool member. This trace grows by one checkpoint per epoch in which the pool member modifies their balance (via `enter_delegation_pool`, `add_to_delegation_pool`, `exit_delegation_pool_intent`, or `switch_delegation_pool`). The `insert` function in the trace only deduplicates writes within the **same** epoch key (`current_epoch + K`); writes in different epochs always append a new checkpoint:

```cairo
if last.key == key {
    last.value = value;
    checkpoints[len - 1].write(last);
} else {
    assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
``` [2](#0-1) 

The `entry_to_claim_from` cursor stored in `pool_member_info` is only advanced inside `claim_rewards`:

```cairo
pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
``` [3](#0-2) 

If a pool member never calls `claim_rewards`, `entry_to_claim_from` stays at `0`, and every subsequent `claim_rewards` call must iterate over the entire accumulated trace from the beginning. Each iteration performs at least two storage reads (`pool_member_trace.at(...)` and `find_sigma` which reads `cumulative_rewards_trace`), making the gas cost grow linearly with the number of unclaimed epochs. [4](#0-3) 

### Impact Explanation
When the trace length exceeds the gas budget of a single Starknet transaction, `claim_rewards` will always revert. Because `entry_to_claim_from` is only updated inside the same transaction that transfers rewards, a failed transaction leaves the cursor unchanged. There is no alternative entry point to partially drain the trace or split the claim. The pool member's entire accumulated unclaimed yield becomes permanently inaccessible — matching the **High** impact category: *Permanent freezing of unclaimed yield*.

### Likelihood Explanation
**Medium.** The trace grows by at most one entry per epoch in which the member changes their balance. A long-term delegator who adjusts their position (adds or partially exits) across hundreds of epochs without claiming rewards will silently accumulate a trace large enough to breach gas limits. The developers themselves acknowledge the loop is unbounded (the comment reads "unlikely to exceed gas limits"), indicating awareness but no mitigation. No privileged role or external compromise is required — only normal pool member actions over time.

### Recommendation
Replace the unbounded loop with a paginated claim mechanism: allow `claim_rewards` to accept an optional `max_entries` parameter and process only that many checkpoints per call, advancing `entry_to_claim_from` incrementally. Alternatively, enforce a maximum trace length by requiring pool members to claim rewards before their trace exceeds a configurable cap, or automatically claim on every balance-change operation.

### Proof of Concept
1. Pool member `A` enters a delegation pool at epoch `E0`.
2. Each epoch, `A` calls `add_to_delegation_pool` (or `exit_delegation_pool_intent`) with a small amount, appending one new checkpoint to `pool_member_epoch_balance[A]` per epoch.
3. `A` never calls `claim_rewards`, so `entry_to_claim_from` remains `0`.
4. After `N` epochs (where `N` is large enough that iterating `N` storage reads + `find_sigma` calls exceeds the Starknet per-transaction gas cap), `A` calls `claim_rewards`.
5. The loop at line 859 of `pool.cairo` attempts to iterate all `N` entries; the transaction runs out of gas and reverts.
6. Because the revert leaves `entry_to_claim_from = 0` in storage, every future `claim_rewards` attempt also reverts. `A`'s accumulated yield is permanently frozen. [5](#0-4) [6](#0-5)

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

**File:** src/pool/pool.cairo (L844-877)
```text
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
