### Title
Unbounded `pool_member_epoch_balance` Trace Causes Unbounded Gas Consumption in `calculate_rewards`, Permanently Freezing Unclaimed Yield - (File: src/pool/pool.cairo)

---

### Summary

The `calculate_rewards` function in `src/pool/pool.cairo` iterates over a pool member's entire `pool_member_epoch_balance` trace from the last claimed position to the current epoch. The trace grows by one entry per epoch in which the pool member makes a balance change. There is no cap on trace length. A pool member who makes one balance change per epoch without claiming rewards will eventually accumulate a trace so large that `claim_rewards` (and `pool_member_info_v1`) exceed the Starknet per-transaction gas limit, permanently freezing their unclaimed yield.

---

### Finding Description

**Root cause — the unbounded loop in `calculate_rewards`:**

The code itself acknowledges the risk with an explicit comment:

```
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
``` [1](#0-0) 

The loop reads one storage slot per iteration (`pool_member_trace.at(entry_to_claim_from)`) and calls `find_sigma` on each, making each iteration expensive. The loop runs from `entry_to_claim_from` (the cursor saved at the last `claim_rewards` call) up to the current epoch boundary.

**How the trace grows:**

Every call to `set_member_balance` or `increase_member_balance` inserts a checkpoint keyed at `current_epoch + K`: [2](#0-1) 

The underlying `insert` function only merges two writes if they share the same epoch key; writes in different epochs always append a new `Vec` entry: [3](#0-2) 

Therefore, one balance-changing call per epoch adds one permanent entry to the trace. The following public entry points all trigger a balance write:

- `enter_delegation_pool` → `set_member_balance` [4](#0-3) 
- `add_to_delegation_pool` → `increase_member_balance` [5](#0-4) 
- `exit_delegation_pool_intent` → `set_member_balance` [6](#0-5) 

**Affected callers of `calculate_rewards`:**

1. `claim_rewards` — state-changing, callable by the pool member or their reward address: [7](#0-6) 
2. `pool_member_info_v1` — view function, callable by anyone: [8](#0-7) 

**No limit exists** on the length of `pool_member_epoch_balance`: [9](#0-8) 

---

### Impact Explanation

Once the trace is large enough that `calculate_rewards` exceeds the Starknet transaction gas limit, every call to `claim_rewards` for that pool member will revert. Because `entry_to_claim_from` is only advanced inside a successful `claim_rewards` execution, the cursor never moves forward, and the condition `entry_to_claim_from < pool_member_trace_length` remains permanently true with an ever-growing gap. The pool member's accrued yield is permanently frozen and unclaimable.

This matches the allowed impact: **Permanent freezing of unclaimed yield (High)**.

---

### Likelihood Explanation

An unprivileged pool member (delegator) is the sole actor required. The attack path is:

1. Call `add_to_delegation_pool` with a minimal amount once per epoch (the minimum non-zero amount satisfies the only guard: `assert!(amount.is_non_zero())`).
2. Never call `claim_rewards` between steps, so `entry_to_claim_from` stays at 0.
3. After enough epochs the trace length exceeds the gas budget for one transaction.

The cost per epoch is one `add_to_delegation_pool` transaction plus the token transfer. This is a low-cost, slow-burn attack identical in structure to the Hats Protocol `changeHatDetails` incremental attack described in the reference report. The attacker can also make the situation irreversible by calling `exit_delegation_pool_intent` for their full balance (setting balance to zero) and then never completing the exit, leaving the trace intact but the pool member unable to claim.

---

### Recommendation

1. **Enforce a maximum trace length per pool member.** Reject any balance-changing call that would push `pool_member_epoch_balance.length()` beyond a safe cap (e.g., 1000 entries).
2. **Alternatively, require periodic claiming.** Reject balance changes if `entry_to_claim_from` lags the current trace length by more than a fixed window, forcing the member to claim before making further changes.
3. **Paginated claiming.** Allow `claim_rewards` to accept a `max_entries` parameter so rewards can be claimed in batches, preventing a single transaction from needing to process the entire trace.

---

### Proof of Concept

```
Epoch 1:  pool_member calls add_to_delegation_pool(1 STRK)
          → pool_member_epoch_balance trace length = 1

Epoch 2:  pool_member calls add_to_delegation_pool(1 STRK)
          → trace length = 2

...

Epoch N:  pool_member calls add_to_delegation_pool(1 STRK)
          → trace length = N

pool_member calls claim_rewards(pool_member):
  → calculate_rewards loops N times, each reading storage + find_sigma
  → at sufficiently large N, transaction reverts with out-of-gas
  → entry_to_claim_from remains 0
  → all subsequent claim_rewards calls also revert
  → unclaimed yield is permanently frozen
```

The `pool_member_info_v1` view function suffers the same revert for any caller querying this pool member's info, matching the DOS pattern of `Hats.uri` in the reference report. [10](#0-9)

### Citations

**File:** src/pool/pool.cairo (L107-108)
```text
        /// Map pool member to their epoch-balance info.
        pool_member_epoch_balance: Map<ContractAddress, PoolMemberBalanceTrace>,
```

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

**File:** src/pool/pool.cairo (L349-355)
```text
            let (mut rewards, updated_entry_to_claim_from) = self
                .calculate_rewards(
                    :pool_member,
                    from_checkpoint: pool_member_info.reward_checkpoint,
                    :until_checkpoint,
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
```

**File:** src/pool/pool.cairo (L528-548)
```text
        fn pool_member_info_v1(
            self: @ContractState, pool_member: ContractAddress,
        ) -> PoolMemberInfoV1 {
            let pool_member_info = self.internal_pool_member_info(:pool_member);
            let (rewards, _) = self
                .calculate_rewards(
                    :pool_member,
                    from_checkpoint: pool_member_info.reward_checkpoint,
                    until_checkpoint: self.get_current_checkpoint(:pool_member),
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
            let external_pool_member_info = PoolMemberInfoV1 {
                reward_address: pool_member_info.reward_address,
                amount: self.get_last_member_balance(:pool_member),
                unclaimed_rewards: pool_member_info._unclaimed_rewards_from_v0 + rewards,
                commission: self.get_commission_from_staking_contract(),
                unpool_amount: pool_member_info.unpool_amount,
                unpool_time: pool_member_info.unpool_time,
            };
            external_pool_member_info
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
