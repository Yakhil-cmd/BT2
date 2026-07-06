### Title
Unbounded Loop in `calculate_rewards` Can Permanently Freeze Delegator's Unclaimed Yield — (File: src/pool/pool.cairo)

---

### Summary

The `calculate_rewards` function in the pool contract contains an explicitly acknowledged unbounded loop that iterates over all balance-change entries in a pool member's trace since their last claim. A delegator who makes repeated balance changes across many epochs without claiming rewards accumulates an ever-growing trace. Once the trace is large enough, every call to `claim_rewards` will exceed the Starknet block gas limit, permanently freezing the delegator's unclaimed yield with no recovery path.

---

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` iterates over every entry in `pool_member_epoch_balance` from `entry_to_claim_from` up to the current epoch:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch { break; }
    let to_sigma = self.find_sigma(pool_member_checkpoint, curr_epoch: until_epoch);
    rewards += compute_rewards_rounded_down(...);
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

Each call to `set_member_balance` inserts a new entry into the trace keyed at `current_epoch + K`:

```cairo
trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance);
``` [2](#0-1) 

The `insert` implementation only overwrites the last entry when the key matches; otherwise it appends a new checkpoint:

```cairo
if last.key == key {
    last.value = value;
    checkpoints[len - 1].write(last);
} else {
    assert!(last.key < key, ...);
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
``` [3](#0-2) 

Consequently, every balance change made in a distinct epoch (via `add_to_delegation_pool`, `increase_delegation`, or `exit_delegation_pool_intent`) appends a new, permanent entry to the trace. The `entry_to_claim_from` cursor is only advanced on a successful `claim_rewards` call:

```cairo
pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
pool_member_info.reward_checkpoint = until_checkpoint;
``` [4](#0-3) 

If `claim_rewards` reverts (due to gas exhaustion), the cursor is never updated, so every subsequent call re-attempts the same oversized loop and reverts again — a permanent deadlock.

The same loop is also executed inside the view function `pool_member_info_v1`:

```cairo
let (rewards, _) = self.calculate_rewards(
    :pool_member,
    from_checkpoint: pool_member_info.reward_checkpoint,
    until_checkpoint: self.get_current_checkpoint(:pool_member),
    entry_to_claim_from: pool_member_info.entry_to_claim_from,
);
``` [5](#0-4) 

This means even read-only queries about the delegator's state would fail once the trace is large enough.

---

### Impact Explanation

A delegator whose `pool_member_epoch_balance` trace grows beyond the gas-per-transaction threshold will find that `claim_rewards` always reverts. Because there is no partial-claim or batch mechanism, and because the cursor is only advanced on success, the delegator's entire accumulated unclaimed yield becomes permanently inaccessible. This maps to **High: Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

The trace grows by at most one entry per epoch (multiple changes within the same epoch overwrite the same slot). The rate of growth therefore equals the epoch frequency. The developers themselves acknowledge the risk in the comment "This loop is unbounded but unlikely to exceed gas limits," confirming the issue is known but unmitigated. A delegator who makes one balance change per epoch and defers claiming for a sufficiently long period (the exact threshold depends on Starknet's per-transaction gas ceiling and the cost of each `find_sigma` call, which itself reads from `cumulative_rewards_trace`) will eventually hit the limit. Because there is no on-chain warning or cap, the delegator has no way to know they are approaching the threshold before it is too late.

---

### Recommendation

1. **Add a maximum iteration cap** to the loop in `calculate_rewards`, reverting or returning partial results if the cap is reached, and store the updated `entry_to_claim_from` so subsequent calls continue from where the previous one stopped.
2. **Expose a partial-claim entry point** that accepts an explicit `max_entries` parameter, allowing delegators to drain their trace incrementally.
3. **Emit a warning event** (or enforce a hard limit) when `pool_member_epoch_balance` length exceeds a safe threshold, analogous to the protocol-wide fee cap recommended in H-09.

---

### Proof of Concept

1. Delegator calls `delegate` to enter a pool.
2. Each epoch, delegator calls `increase_delegation` with a minimal amount (1 token). Each call in a new epoch appends one entry to `pool_member_epoch_balance` via `set_member_balance` → `trace.insert(key: current_epoch + K, ...)`.
3. Delegator never calls `claim_rewards`, so `entry_to_claim_from` stays at 0.
4. After N epochs, `pool_member_trace_length == N`.
5. Delegator calls `claim_rewards`. The loop executes N iterations, each reading from storage and calling `find_sigma`. For sufficiently large N, the transaction exceeds the Starknet block gas limit and reverts.
6. Every subsequent `claim_rewards` call also reverts. The delegator's accumulated rewards are permanently frozen. [6](#0-5) [7](#0-6)

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

**File:** src/pool/pool.cairo (L532-538)
```text
            let (rewards, _) = self
                .calculate_rewards(
                    :pool_member,
                    from_checkpoint: pool_member_info.reward_checkpoint,
                    until_checkpoint: self.get_current_checkpoint(:pool_member),
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L163-174)
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
        (prev, value)
```
