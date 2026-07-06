### Title
Unbounded Loop in `calculate_rewards` Can Permanently Freeze Pool Member's Unclaimed Yield — (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` internal function in the delegation pool contract contains an explicitly acknowledged unbounded loop that iterates over a pool member's entire `pool_member_epoch_balance` trace. A pool member who makes repeated balance changes across many distinct epochs without claiming rewards will grow this trace without bound. Once the trace is large enough, every call to `claim_rewards` will exceed Starknet's gas limits and revert, permanently freezing the pool member's unclaimed yield with no recovery path.

---

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` iterates over every entry in the `pool_member_epoch_balance` trace that has not yet been processed:

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
``` [1](#0-0) 

The trace grows by one entry per distinct epoch in which a balance change occurs. Each call to `set_member_balance` (invoked by both `add_to_delegation_pool` and `exit_delegation_pool_intent`) inserts a new checkpoint keyed at `current_epoch + K`:

```cairo
fn set_member_balance(ref self: ContractState, pool_member: ContractAddress, amount: Amount) {
    let trace = self.pool_member_epoch_balance.entry(pool_member);
    ...
    trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance);
}
``` [2](#0-1) 

The `entry_to_claim_from` cursor stored in `pool_member_info` advances only upon a *successful* `claim_rewards` call:

```cairo
pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
pool_member_info.reward_checkpoint = until_checkpoint;
``` [3](#0-2) 

If `claim_rewards` reverts (gas exhaustion), the cursor is never advanced, so every subsequent attempt must re-process the same oversized trace. There is no partial-claim or cursor-reset mechanism.

The `claim_rewards` entrypoint itself performs only a lightweight authorization check before invoking the unbounded loop:

```cairo
fn claim_rewards(ref self: ContractState, pool_member: ContractAddress) -> Amount {
    let mut pool_member_info = self.internal_pool_member_info(:pool_member);
    let caller_address = get_caller_address();
    ...
    let (mut rewards, updated_entry_to_claim_from) = self
        .calculate_rewards(
            :pool_member,
            from_checkpoint: pool_member_info.reward_checkpoint,
            :until_checkpoint,
            entry_to_claim_from: pool_member_info.entry_to_claim_from,
        );
``` [4](#0-3) 

---

### Impact Explanation

Once the `pool_member_epoch_balance` trace for a given pool member grows beyond the gas budget that a single Starknet transaction can afford, every call to `claim_rewards` for that member will revert unconditionally. Because there is no partial-claim path and no way to reset `entry_to_claim_from` externally, the pool member's accumulated STRK rewards are permanently inaccessible. This matches the allowed impact: **Permanent freezing of unclaimed yield (High)**.

---

### Likelihood Explanation

The pool member or their reward address controls the rate of trace growth via `add_to_delegation_pool` and `exit_delegation_pool_intent`. Each call in a new epoch appends one entry. A delegator who actively re-delegates or adjusts their position across many epochs without claiming will accumulate entries linearly. The developers themselves flag this risk in the source comment ("This loop is unbounded but unlikely to exceed gas limits"), acknowledging the absence of a hard bound. Likelihood is **Low-to-Medium**: it requires sustained activity over many epochs without claiming, but no external actor is needed and no privileged role is required.

---

### Recommendation

1. **Short term**: Introduce a maximum number of trace entries processed per `claim_rewards` call (a "partial claim" pattern), advancing `entry_to_claim_from` by at most `MAX_ENTRIES_PER_CLAIM` per transaction and storing the updated cursor even when rewards are zero. This ensures the function always terminates within gas limits.
2. **Long term**: Enforce a maximum trace length per pool member (e.g., by compacting old entries on each balance change), or add a governance-controlled cap on how many epochs can accumulate without a claim before further balance changes are blocked.

---

### Proof of Concept

1. Pool member Alice enters the delegation pool at epoch 0.
2. Alice calls `add_to_delegation_pool` once per epoch for N epochs (e.g., N = 2 000), never calling `claim_rewards`. Each call in a new epoch appends one entry to `pool_member_epoch_balance` via `set_member_balance` → `trace.insert(key: epoch + K, ...)`.
3. After N epochs, Alice's trace has N entries and `entry_to_claim_from = 0`.
4. Alice (or her reward address) calls `claim_rewards`. The `calculate_rewards` loop attempts to iterate over all N entries, each requiring a storage read (`pool_member_trace.at(entry_to_claim_from)`). The transaction exceeds Starknet's gas limit and reverts.
5. `entry_to_claim_from` remains 0. Every future `claim_rewards` call faces the same N-entry loop and reverts identically.
6. Alice's accumulated STRK rewards are permanently frozen with no recovery path. [1](#0-0) [2](#0-1) [5](#0-4)

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

**File:** src/pool/pool.cairo (L358-359)
```text
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
