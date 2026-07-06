### Title
Unbounded Loop Over Pool Member Balance Trace in `calculate_rewards` Can Permanently Freeze Unclaimed Yield - (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` function in `src/pool/pool.cairo` contains an explicitly acknowledged unbounded `while` loop that iterates over a pool member's entire `pool_member_epoch_balance` trace. Because each balance-modifying action (deposit, partial exit) appends one new entry per epoch to this trace, a delegator who makes frequent balance changes without claiming rewards will accumulate a trace large enough to cause `claim_rewards` to exceed Starknet's gas limit, permanently freezing their unclaimed yield.

---

### Finding Description

`calculate_rewards` iterates over every entry in `pool_member_epoch_balance` from `entry_to_claim_from` up to the current trace length:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch {
        break;
    }
    ...
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

The trace grows via `set_member_balance`, which calls `trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance)`: [2](#0-1) 

The `insert` implementation in the trace only appends a **new** checkpoint when the epoch key differs from the last entry's key. Since `get_epoch_plus_k()` returns `current_epoch + K` (K=2), each epoch can contribute at most one new entry: [3](#0-2) 

`set_member_balance` is called by both `increase_member_balance` (used in `add_to_delegation_pool` and `enter_delegation_pool`) and directly by `exit_delegation_pool_intent`: [4](#0-3) [5](#0-4) 

The `entry_to_claim_from` cursor is stored in `pool_member_info` and only advances when `claim_rewards` succeeds: [6](#0-5) 

If a pool member never calls `claim_rewards`, `entry_to_claim_from` stays at 0 while the trace grows by one entry per epoch. After N epochs of balance changes, the loop must traverse all N entries in a single transaction.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Once the trace is large enough that iterating it in a single transaction exceeds Starknet's gas limit, every call to `claim_rewards` for that pool member will revert. The pool member's accumulated rewards become permanently inaccessible. The `entry_to_claim_from` cursor can never advance past the gas-limit boundary, so there is no recovery path within the current contract design.

---

### Likelihood Explanation

**Medium.** The protocol is designed for long-term participation. A delegator who adjusts their position once per epoch (e.g., topping up or partially exiting) and defers reward claims — a completely normal usage pattern — will accumulate one trace entry per epoch. With short epoch lengths (e.g., a few hours), hundreds to thousands of entries can accumulate over months. The developers themselves flag this in a code comment: *"This loop is unbounded but unlikely to exceed gas limits"* — acknowledging the risk while betting on practical limits. [7](#0-6) 

---

### Recommendation

1. **Paginate reward claims**: Allow `claim_rewards` to accept a `max_entries` parameter so the loop processes a bounded number of trace entries per call, advancing `entry_to_claim_from` incrementally across multiple transactions.
2. **Enforce a claim cadence**: Require or incentivize pool members to claim rewards at least once every M epochs, preventing unbounded trace accumulation.
3. **Compress the trace on claim**: After processing entries up to `until_epoch`, remove or compact those entries from storage so the trace never grows beyond a bounded window.

---

### Proof of Concept

1. Attacker (delegator) calls `enter_delegation_pool` with a minimal amount in epoch E.
2. Each subsequent epoch, the delegator calls `add_to_delegation_pool` with 1 token (or `exit_delegation_pool_intent` with 0 amount to re-set balance). Each call appends one entry to `pool_member_epoch_balance` via `set_member_balance` → `trace.insert`.
3. The delegator never calls `claim_rewards`, so `entry_to_claim_from` remains 0.
4. After N epochs, the trace has N entries.
5. The delegator (or anyone) calls `claim_rewards`. `calculate_rewards` enters the `while` loop and must iterate all N entries before `pool_member_checkpoint.epoch() >= until_epoch` triggers the break.
6. At sufficiently large N (determined by Starknet's per-transaction gas cap), the transaction reverts with an out-of-gas error.
7. All subsequent `claim_rewards` calls also revert. The unclaimed yield is permanently frozen. [8](#0-7)

### Citations

**File:** src/pool/pool.cairo (L277-279)
```text
            // Update the pool member's balance checkpoint.
            self.set_member_balance(:pool_member, amount: new_delegated_stake);

```

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

**File:** src/pool/pool.cairo (L734-740)
```text
        fn increase_member_balance(
            ref self: ContractState, pool_member: ContractAddress, amount: Amount,
        ) -> Amount {
            let current_balance = self.get_last_member_balance(:pool_member);
            self.set_member_balance(:pool_member, amount: current_balance + amount);
            current_balance
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
