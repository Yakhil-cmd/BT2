### Title
Unbounded loop over growing `pool_member_epoch_balance` trace in `calculate_rewards` can permanently freeze delegator's unclaimed rewards - (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` internal function in `src/pool/pool.cairo` contains an explicitly acknowledged unbounded loop that iterates over a per-delegator balance-change trace (`pool_member_epoch_balance`). This trace grows by one entry every time a delegator modifies their delegation balance. If a delegator accumulates enough balance-change entries without claiming rewards, the loop will exceed Starknet's gas/resource limits when `claim_rewards` is eventually called, permanently freezing that delegator's unclaimed yield.

---

### Finding Description

In `src/pool/pool.cairo`, the internal function `calculate_rewards` iterates over every entry in `pool_member_epoch_balance` for a given pool member:

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

The trace `pool_member_epoch_balance` is a `Map<ContractAddress, PoolMemberBalanceTrace>` stored in contract storage: [2](#0-1) 

A new entry is appended to this trace (at key `current_epoch + K`) every time `set_member_balance` is called: [3](#0-2) 

`set_member_balance` is invoked from every balance-modifying public entrypoint:

- `enter_delegation_pool` (line 201) — initial delegation
- `add_to_delegation_pool` (line 242) — increasing delegation
- `exit_delegation_pool_intent` (line 278) — signaling partial/full exit [4](#0-3) [5](#0-4) 

There is no cap on how many times a delegator may call these functions across epochs, and there is no mechanism to prune old trace entries. The developers themselves acknowledge the risk in the comment at line 858: *"This loop is unbounded but unlikely to exceed gas limits."*

---

### Impact Explanation

When a delegator calls `claim_rewards` (or any path that invokes `calculate_rewards`), the loop must traverse every balance-change entry in `pool_member_epoch_balance` that falls before the current epoch. If this count is large enough to exhaust Starknet's per-transaction resource limits, the transaction reverts. Because there is no way to prune the trace or claim rewards in batches, the delegator's accumulated unclaimed yield becomes permanently inaccessible.

**Impact class**: Permanent freezing of unclaimed yield (High, per the allowed impact scope).

---

### Likelihood Explanation

Any unprivileged delegator can grow their own trace by repeatedly calling `add_to_delegation_pool` or `exit_delegation_pool_intent` across many epochs. Each call costs only a normal transaction fee. A delegator who defers claiming rewards for a long time while actively adjusting their delegation will accumulate entries organically. A malicious actor who controls their own reward address (which is also permitted to call `add_to_delegation_pool`) could deliberately inflate the trace to self-grief or to demonstrate the issue. No privileged access, bridge compromise, or external dependency is required.

---

### Recommendation

1. **Cap the trace length per pool member**: Enforce a maximum number of balance-change entries (e.g., 1 per epoch) by overwriting the existing entry for `current_epoch + K` rather than appending a new one when the key already exists.
2. **Paginated / checkpointed claiming**: Store `entry_to_claim_from` in the pool member's persistent info so that each `claim_rewards` call only processes a bounded window of new entries, and allow multiple partial-claim calls.
3. **Periodic trace compaction**: After a successful claim, delete or compact all trace entries that have already been processed.

---

### Proof of Concept

A delegator calls `add_to_delegation_pool` (or alternates between `add_to_delegation_pool` and `exit_delegation_pool_intent`) once per epoch for N epochs without ever calling `claim_rewards`. Each call appends one entry to `pool_member_epoch_balance`. After N epochs, calling `claim_rewards` triggers `calculate_rewards`, which must iterate over all N entries. As N grows, the gas cost grows linearly. Once N exceeds the per-transaction resource limit, every `claim_rewards` call reverts, permanently freezing the delegator's accumulated yield.

The developers have already identified this risk in the source code: [6](#0-5)

### Citations

**File:** src/pool/pool.cairo (L107-109)
```text
        /// Map pool member to their epoch-balance info.
        pool_member_epoch_balance: Map<ContractAddress, PoolMemberBalanceTrace>,
        /// Map version to class hash of the contract.
```

**File:** src/pool/pool.cairo (L221-253)
```text
        fn add_to_delegation_pool(
            ref self: ContractState, pool_member: ContractAddress, amount: Amount,
        ) -> Amount {
            // Asserts.
            self.assert_staker_is_active();
            let pool_member_info = self.internal_pool_member_info(:pool_member);
            let caller_address = get_caller_address();
            assert!(
                caller_address == pool_member || caller_address == pool_member_info.reward_address,
                "{}",
                Error::CALLER_CANNOT_ADD_TO_POOL,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);

            // Transfer funds from the delegator to the staking contract.
            let token_dispatcher = self.token_dispatcher.read();
            let staker_address = self.staker_address.read();
            transfer_from_delegator(pool_member: caller_address, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);

            // Update the pool member's balance checkpoint.
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
            let new_delegated_stake = old_delegated_stake + amount;

            // Emit events.
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake, new_delegated_stake,
                    },
                );

            new_delegated_stake
```

**File:** src/pool/pool.cairo (L256-293)
```text
        fn exit_delegation_pool_intent(ref self: ContractState, amount: Amount) {
            // Asserts.
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let old_delegated_stake = self.get_last_member_balance(:pool_member);
            let total_amount = old_delegated_stake + pool_member_info.unpool_amount;
            assert!(amount <= total_amount, "{}", GenericError::AMOUNT_TOO_HIGH);

            // Notify the staking contract of the removal intent.
            let unpool_time = self.undelegate_from_staking_contract_intent(:pool_member, :amount);

            // Edit the pool member to reflect the removal intent, and write to storage.
            if amount.is_zero() {
                pool_member_info.unpool_time = Option::None;
            } else {
                pool_member_info.unpool_time = Option::Some(unpool_time);
            }
            pool_member_info.unpool_amount = amount;
            let new_delegated_stake = total_amount - amount;
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Update the pool member's balance checkpoint.
            self.set_member_balance(:pool_member, amount: new_delegated_stake);

            // Emit events.
            self
                .emit(
                    Events::PoolMemberExitIntent {
                        pool_member, exit_timestamp: unpool_time, amount,
                    },
                );
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake, new_delegated_stake,
                    },
                );
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
