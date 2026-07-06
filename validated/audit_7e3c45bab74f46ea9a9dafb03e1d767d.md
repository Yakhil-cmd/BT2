### Title
Unbounded Loop in `calculate_rewards` Allows Permanent Freezing of Delegator Unclaimed Yield - (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` internal function in the Pool contract contains an explicitly acknowledged unbounded loop that iterates over a delegator's entire `pool_member_epoch_balance` trace. A delegator who makes many balance changes across distinct epochs without claiming rewards will accumulate an arbitrarily large trace. When `claim_rewards` is eventually called, the loop iterates over all unclaimed entries, potentially exceeding Starknet's block gas limit and permanently freezing the delegator's unclaimed yield.

---

### Finding Description

The `calculate_rewards` function in `src/pool/pool.cairo` iterates over the `pool_member_epoch_balance` trace for a given pool member:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch {
        break;
    }
    let to_sigma = self.find_sigma(pool_member_checkpoint, curr_epoch: until_epoch);
    rewards += compute_rewards_rounded_down(...);
    entry_to_claim_from += 1;
}
```

The `pool_member_epoch_balance` trace grows by one entry per call to `set_member_balance` when the epoch key differs from the last stored key. `set_member_balance` is called by:

- `increase_member_balance` → called by `add_to_delegation_pool` (delegator increases stake)
- `set_member_balance` directly → called by `exit_delegation_pool_intent` (delegator reduces stake)
- `enter_delegation_pool_from_staking_contract` (pool switch)

The `insert` function in the trace only deduplicates if the same epoch key is reused; each balance change at a new epoch appends a fresh checkpoint. The `entry_to_claim_from` pointer advances only when `claim_rewards` is successfully executed. If a delegator defers claiming rewards while making many balance changes across many distinct epochs, the trace accumulates unboundedly.

When `claim_rewards` is finally called, it calls `calculate_rewards` which loops over all entries from `entry_to_claim_from` to the current epoch. Each iteration also calls `find_sigma`, which performs additional storage reads. With a sufficiently large trace, the transaction exceeds the block gas limit and reverts, making it impossible to ever claim rewards.

---

### Impact Explanation

**Permanent freezing of unclaimed yield.** Once the trace is large enough that `claim_rewards` always exceeds the block gas limit, the delegator's accumulated rewards are permanently locked in the Pool contract. There is no partial-claim mechanism and no way to reset `entry_to_claim_from` without a successful `claim_rewards` call. The delegator's principal can still be withdrawn via `exit_delegation_pool_intent` / `exit_delegation_pool_action` (those paths do not iterate the trace), but all accrued yield is irrecoverable.

This matches the allowed impact: **Permanent freezing of unclaimed yield or unclaimed royalties**.

---

### Likelihood Explanation

The attack is self-inflicted but realistic in two scenarios:

1. **Deliberate griefing by a third party is not possible** — only the delegator themselves can call `add_to_delegation_pool` or `exit_delegation_pool_intent` for their own account. However, a delegator who actively manages their position (e.g., a bot that rebalances stake every epoch) will naturally accumulate a large trace over time without realizing the consequence.

2. **Long-lived delegators with frequent rebalancing** — over hundreds or thousands of epochs (Starknet epochs are short), a delegator who changes their balance each epoch and never claims rewards will hit the limit. The protocol has no mechanism to warn or prevent this.

Likelihood is **medium**: it requires a specific usage pattern (many balance changes, infrequent reward claims) but no privileged access, no external dependency, and no attacker cooperation.

---

### Recommendation

1. **Bound the loop**: Introduce a maximum number of iterations per `claim_rewards` call (e.g., process at most `MAX_ENTRIES` checkpoints per call) and persist the updated `entry_to_claim_from` even on a partial claim, allowing the delegator to call `claim_rewards` multiple times to drain the full trace.

2. **Benchmark gas per iteration**: Measure the gas cost of one loop iteration (including `find_sigma` storage reads) and set a safe upper bound on trace length before rewards become unclaimable.

3. **Emit a warning or enforce a cap** on the number of balance changes a pool member can make without claiming rewards.

---

### Proof of Concept

**Setup**: Delegator `D` joins a pool. Over `N` consecutive epochs (where `N` is large enough to exceed the gas limit), `D` calls `add_to_delegation_pool` once per epoch (each call at a new epoch appends a new checkpoint to `pool_member_epoch_balance`). `D` never calls `claim_rewards`.

**Trigger**: After `N` epochs, `D` calls `claim_rewards`.

**Execution path**:

1. `claim_rewards` → `calculate_rewards` with `entry_to_claim_from = 0` and `pool_member_trace_length = N`. [1](#0-0) 

2. The `while` loop runs `N` times; each iteration reads `pool_member_trace.at(entry_to_claim_from)` (storage read) and calls `find_sigma` (additional storage reads). [2](#0-1) 

3. For sufficiently large `N`, the transaction exceeds Starknet's block gas limit and reverts. Because `entry_to_claim_from` is only written on success, it remains at `0`, and every subsequent `claim_rewards` call also reverts.

**Trace growth mechanism** — `set_member_balance` calls `trace.insert` with key `current_epoch + K`; if this key differs from the last stored key, a new checkpoint is appended: [3](#0-2) [4](#0-3) 

The team's own comment acknowledges the risk: *"This loop is unbounded but unlikely to exceed gas limits"* — this is an optimistic assumption that does not hold for active delegators over long time horizons. [5](#0-4)

### Citations

**File:** src/pool/pool.cairo (L335-355)
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
