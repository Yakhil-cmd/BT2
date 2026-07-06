### Title
Unbounded Loop in `calculate_rewards` Over Pool Member Balance Trace Enables Permanent Freezing of Unclaimed Yield - (File: `src/pool/pool.cairo`)

### Summary

The `calculate_rewards` internal function in the Pool contract iterates over the entire `pool_member_epoch_balance` trace for a given pool member without any bound. A delegator who accumulates a sufficiently large balance trace (by making balance changes across many epochs without claiming rewards) will eventually be unable to claim their rewards, permanently freezing their unclaimed yield.

### Finding Description

In `src/pool/pool.cairo`, the `calculate_rewards` function (lines 837–888) contains an unbounded `while` loop that iterates over every entry in the `pool_member_epoch_balance` trace between the last claimed checkpoint and the current epoch:

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

The trace grows via `set_member_balance` (line 718) and `increase_member_balance` (line 734), both of which call `trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance)`. The `insert` function in `src/pool/pool_member_balance_trace/trace.cairo` (lines 152–175) appends a **new checkpoint** whenever the insertion epoch differs from the last stored epoch. This means each balance change in a distinct epoch adds one entry to the trace.

Balance changes are triggered by:
- `enter_delegation_pool` → `set_member_balance` (line 201)
- `add_to_delegation_pool` → `increase_member_balance` (line 242)
- `exit_delegation_pool_intent` → `set_member_balance` (line 278)
- `enter_delegation_pool_from_staking_contract` → `set_member_balance` / `increase_member_balance` (lines 456, 464)

The `entry_to_claim_from` cursor stored in `pool_member_info` (line 354) advances with each successful `claim_rewards` call, so the loop only iterates over entries accumulated **since the last claim**. However, if a delegator makes one balance change per epoch across N epochs without claiming, the loop must iterate N entries on the next claim. With enough epochs, this transaction will exceed the Starknet gas limit, causing `claim_rewards` to revert permanently.

The developers themselves acknowledge this in the code comment: *"This loop is unbounded but unlikely to exceed gas limits."*

### Impact Explanation

A delegator who makes balance changes (via `add_to_delegation_pool` or `exit_delegation_pool_intent`) across many epochs without claiming rewards will accumulate a large `pool_member_epoch_balance` trace. When they eventually call `claim_rewards`, the `calculate_rewards` loop must iterate over all accumulated entries. Once the trace is large enough, every call to `claim_rewards` will run out of gas and revert, **permanently freezing the delegator's unclaimed yield**. The `entry_to_claim_from` cursor is only advanced inside a successful `claim_rewards` execution, so there is no recovery path once the gas limit is exceeded.

**Impact: High — Permanent freezing of unclaimed yield.**

### Likelihood Explanation

A delegator who actively manages their delegation (adding or partially exiting each epoch) over a long period without regularly claiming rewards will naturally accumulate a large trace. Starknet epochs are protocol-defined time windows; over months or years of active participation, hundreds to thousands of trace entries can accumulate. No special attacker capability is required — this is reachable through normal delegator behavior. The protocol provides no warning or safeguard against this condition.

### Recommendation

1. **Paginate reward claims**: Introduce a `claim_rewards_partial(max_entries: u64)` variant that processes at most `max_entries` trace entries per call, advancing `entry_to_claim_from` incrementally. The full `claim_rewards` can call this internally with a safe bound.
2. **Enforce a maximum trace depth**: Cap the number of balance-change entries that can accumulate between claims, reverting new balance changes if the unclaimed trace depth exceeds a threshold (e.g., 500 entries).
3. **Encourage regular claiming**: Document the risk and consider auto-claiming rewards on every balance change to keep `entry_to_claim_from` current.

### Proof of Concept

1. Delegator calls `enter_delegation_pool` in epoch E₀ — trace length = 1.
2. Each subsequent epoch, delegator calls `add_to_delegation_pool` (or `exit_delegation_pool_intent`) — each call in a new epoch appends one entry to `pool_member_epoch_balance` trace.
3. After N epochs without calling `claim_rewards`, trace length = N + 1.
4. Delegator calls `claim_rewards`. This calls `calculate_rewards` which loops from `entry_to_claim_from = 0` to `N`, calling `find_sigma` on each iteration (a storage read).
5. For sufficiently large N (empirically determinable from Starknet's gas limit and per-iteration cost), the transaction runs out of gas and reverts.
6. Since `entry_to_claim_from` is only updated inside a successful `claim_rewards`, it remains at 0. Every subsequent `claim_rewards` call also reverts. The delegator's accumulated yield is permanently frozen.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** src/pool/pool.cairo (L348-358)
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
