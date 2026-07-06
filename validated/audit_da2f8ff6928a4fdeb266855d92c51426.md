### Title
Unbounded Loop in `calculate_rewards` Enables Permanent Freezing of Pool Member Unclaimed Yield - (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` internal function in the Delegation Pool contract contains an unbounded loop over a pool member's `pool_member_epoch_balance` trace. A pool member who makes frequent balance changes across many epochs without claiming rewards will grow this trace without bound. Once the trace is large enough, any call to `claim_rewards` (or `pool_member_info_v1`) will exceed the Starknet transaction gas limit, permanently freezing the pool member's unclaimed yield with no recovery path.

---

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` iterates over every entry in `pool_member_epoch_balance` from `entry_to_claim_from` up to the current epoch: [1](#0-0) 

The code itself acknowledges the risk with the comment: *"This loop is unbounded but unlikely to exceed gas limits."*

Each entry in the trace is appended by `set_member_balance`, which calls `trace.insert(key: self.get_epoch_plus_k(), ...)`: [2](#0-1) 

The `insert` implementation appends a **new** checkpoint whenever the key (= `current_epoch + K`) differs from the last stored key: [3](#0-2) 

`set_member_balance` / `increase_member_balance` is invoked by every balance-changing operation available to a pool member:

- `enter_delegation_pool` — line 201 [4](#0-3) 
- `add_to_delegation_pool` — line 242 [5](#0-4) 
- `exit_delegation_pool_intent` — line 278 [6](#0-5) 
- `enter_delegation_pool_from_staking_contract` (switch) — lines 456, 464 [7](#0-6) 

Because `entry_to_claim_from` is only advanced inside `claim_rewards`: [8](#0-7) 

a pool member who never claims rewards accumulates one new trace entry per epoch in which they change their balance. After N such epochs, `calculate_rewards` must iterate over N entries. When N is large enough to exhaust the Starknet gas budget, the transaction reverts and the rewards are permanently inaccessible.

The same loop is also triggered by the public view function `pool_member_info_v1`: [9](#0-8) 

---

### Impact Explanation

Once the trace is sufficiently large, every call to `claim_rewards` reverts. There is no partial-claim mechanism and no way to prune the trace. The pool member's accumulated STRK rewards are permanently frozen inside the pool contract. This matches the allowed impact: **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

A pool member who actively manages their delegation — adding or partially exiting once per epoch — without regularly claiming rewards will naturally grow the trace. Starknet epochs are short (configurable, but on the order of hours to days). A member who goes several hundred epochs without claiming while making per-epoch balance changes will hit the gas ceiling. This is a realistic usage pattern, not a contrived one.

Additionally, `add_to_delegation_pool` is callable by the pool member **or their reward address**: [10](#0-9) 

A malicious reward address (e.g., a contract set by the pool member themselves, or a social-engineering scenario) could repeatedly call `add_to_delegation_pool` with dust amounts each epoch to accelerate trace growth.

---

### Recommendation

1. **Checkpoint on every balance change**: When `set_member_balance` is called, compute and store the accrued rewards up to that point, resetting `entry_to_claim_from` and `reward_checkpoint` in `pool_member_info`. This collapses the pending trace to at most 1–2 entries at any time, bounding the loop to O(1).
2. **Alternatively, cap trace growth**: Enforce a maximum number of unclaimed balance-change entries (e.g., 256) and require the pool member to call `claim_rewards` before making further balance changes once the cap is reached.
3. **Remove the "unlikely" assumption**: The comment at line 858 acknowledges the risk but dismisses it. Given Starknet's gas model and the protocol's expected longevity, this assumption will eventually be violated.

---

### Proof of Concept

```
Epoch 1:  pool_member calls add_to_delegation_pool(1 wei)
          → pool_member_epoch_balance trace length = 2 (initial + new)
Epoch 2:  pool_member calls add_to_delegation_pool(1 wei)
          → trace length = 3
...
Epoch N:  pool_member calls add_to_delegation_pool(1 wei)
          → trace length = N+1

pool_member calls claim_rewards():
  → calculate_rewards loops over N+1 entries
  → if N > gas_limit_threshold, transaction reverts
  → pool_member's accumulated rewards are permanently frozen
```

The pool member's `entry_to_claim_from` remains 0 throughout (never updated because `claim_rewards` was never successfully called), so every subsequent attempt also reverts.

### Citations

**File:** src/pool/pool.cairo (L201-201)
```text
            self.set_member_balance(:pool_member, :amount);
```

**File:** src/pool/pool.cairo (L227-232)
```text
            let caller_address = get_caller_address();
            assert!(
                caller_address == pool_member || caller_address == pool_member_info.reward_address,
                "{}",
                Error::CALLER_CANNOT_ADD_TO_POOL,
            );
```

**File:** src/pool/pool.cairo (L242-242)
```text
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
```

**File:** src/pool/pool.cairo (L278-278)
```text
            self.set_member_balance(:pool_member, amount: new_delegated_stake);
```

**File:** src/pool/pool.cairo (L349-358)
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
```

**File:** src/pool/pool.cairo (L456-464)
```text
                    self.increase_member_balance(:pool_member, :amount);
                    VInternalPoolMemberInfoTrait::wrap_latest(value: pool_member_info)
                },
                Option::None => {
                    // Pool member does not exist. Create a new record.
                    let reward_address = switch_pool_data.reward_address;

                    // Update the pool member's balance checkpoint.
                    self.set_member_balance(:pool_member, :amount);
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
