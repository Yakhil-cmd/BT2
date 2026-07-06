### Title
Unbounded `pool_member_epoch_balance` Trace Enables Permanent Freezing of Delegator Unclaimed Yield — (File: `src/pool/pool.cairo`)

---

### Summary
A pool member (delegator) can deliberately grow their `pool_member_epoch_balance` trace to an arbitrarily large size by making one balance-changing call per epoch over many epochs. The `calculate_rewards` function iterates over every entry in this trace with no upper bound. Once the trace is large enough, every call to `claim_rewards` for that pool member will exceed the Starknet transaction gas limit and revert, permanently freezing the pool member's accumulated unclaimed yield inside the pool contract.

---

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` contains an explicit unbounded loop:

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

The loop bound is `pool_member_trace_length`, which is the length of the `pool_member_epoch_balance` storage vec for the given pool member. [2](#0-1) 

A new entry is appended to this vec whenever `set_member_balance` is called with a key (`current_epoch + K`) that differs from the last stored key:

```cairo
fn set_member_balance(ref self: ContractState, pool_member: ContractAddress, amount: Amount) {
    let trace = self.pool_member_epoch_balance.entry(pool_member);
    let pool_member_balance = PoolMemberBalanceTrait::new(
        balance: amount,
        cumulative_rewards_trace_idx: self.cumulative_rewards_trace_length() + 1,
    );
    trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance);
}
``` [3](#0-2) 

The `insert` implementation only updates the last entry if the key matches; otherwise it **appends** a new checkpoint:

```cairo
} else {
    assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
``` [4](#0-3) 

`set_member_balance` is called from `enter_delegation_pool`, `add_to_delegation_pool`, and `exit_delegation_pool_intent`: [5](#0-4) [6](#0-5) [7](#0-6) 

Because the key is `current_epoch + K`, one new trace entry is created per epoch in which the pool member makes a balance change. There is **no cap** on the trace length.

`claim_rewards` is the only path that calls `calculate_rewards`, and it is restricted to the pool member or their reward address:

```cairo
assert!(
    caller_address == pool_member || caller_address == reward_address,
    "{}",
    Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
);
``` [8](#0-7) 

Once the trace is large enough that the loop exceeds the Starknet per-transaction gas limit, `claim_rewards` will always revert, and the pool member's accumulated rewards are permanently locked in the contract with no recovery path.

---

### Impact Explanation

**Permanent freezing of unclaimed yield** (High severity).

The pool member's STRK rewards accumulate in the pool contract but become permanently unclaimable once the trace length causes `calculate_rewards` to exceed the gas limit. There is no administrative function to reset or truncate the trace, and no alternative claim path exists. The funds are locked in the pool contract indefinitely.

---

### Likelihood Explanation

A delegator who makes one balance-modifying call per epoch (e.g., calling `add_to_delegation_pool` with a minimal amount each epoch) grows the trace by one entry per epoch. Starknet epochs are on the order of hours. Over months of operation, a trace of thousands of entries is achievable. Each loop iteration performs multiple storage reads (`pool_member_trace.at(...)`) and arithmetic (`find_sigma`, `compute_rewards_rounded_down`), making the per-iteration gas cost non-trivial. The developers themselves acknowledged the risk in the comment: *"This loop is unbounded but unlikely to exceed gas limits"* — this dismissal does not hold under deliberate manipulation.

The minimum cost to the attacker is the gas for one small `add_to_delegation_pool` call per epoch, which is low relative to the damage caused.

---

### Recommendation

1. **Checkpoint-based partial claiming**: Store `entry_to_claim_from` in `pool_member_info` (it already is) and allow `claim_rewards` to process only a bounded number of trace entries per call (e.g., a configurable `max_entries_per_claim`), resuming from the saved index on the next call.
2. **Trace compaction**: When `claim_rewards` is called, compact processed entries from the trace so the loop length does not grow without bound.
3. **Hard cap on trace length**: Enforce a maximum number of pending (unclaimed) balance-change entries per pool member, reverting `add_to_delegation_pool` / `exit_delegation_pool_intent` if the cap would be exceeded.

---

### Proof of Concept

```
Epoch 1:  delegator calls enter_delegation_pool(amount=MIN)
           → trace length = 1

Epoch 2:  delegator calls add_to_delegation_pool(amount=1)
           → trace length = 2

Epoch 3:  delegator calls add_to_delegation_pool(amount=1)
           → trace length = 3

...

Epoch N:  delegator calls add_to_delegation_pool(amount=1)
           → trace length = N

Epoch N+1: delegator (or reward address) calls claim_rewards(pool_member)
            → calculate_rewards loops N times
            → if N is large enough, transaction reverts with out-of-gas
            → all accumulated rewards are permanently frozen
```

The attacker controls `N` entirely. No privileged access, no external dependency, and no oracle manipulation is required. The only cost is the gas for N small `add_to_delegation_pool` transactions spread across N epochs.

### Citations

**File:** src/pool/pool.cairo (L201-201)
```text
            self.set_member_balance(:pool_member, :amount);
```

**File:** src/pool/pool.cairo (L242-242)
```text
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
```

**File:** src/pool/pool.cairo (L278-278)
```text
            self.set_member_balance(:pool_member, amount: new_delegated_stake);
```

**File:** src/pool/pool.cairo (L340-344)
```text
            assert!(
                caller_address == pool_member || caller_address == reward_address,
                "{}",
                Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L169-173)
```text
        } else {
            // Checkpoint keys must be non-decreasing.
            assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
            checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
        }
```
