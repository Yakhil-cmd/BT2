### Title
Unbounded Loop in `calculate_rewards` Enables Permanent Freezing of Delegator Yield - (`src/pool/pool.cairo`)

---

### Summary

`Pool::claim_rewards` calls `calculate_rewards`, which contains an explicitly acknowledged unbounded loop that iterates over every entry in a pool member's `pool_member_epoch_balance` trace since their last claim. A pool member who makes balance changes across many epochs without claiming rewards will accumulate an arbitrarily large trace, causing `claim_rewards` to run out of gas and permanently freeze their unclaimed yield.

---

### Finding Description

`Pool::calculate_rewards` iterates over the entire `pool_member_epoch_balance` trace from `entry_to_claim_from` to the current epoch:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch { break; }
    let to_sigma = self.find_sigma(pool_member_checkpoint, curr_epoch: until_epoch);
    ...
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

The trace grows via `set_member_balance`, which inserts a new checkpoint at `current_epoch + K` whenever a pool member's balance changes in a new epoch:

```cairo
fn set_member_balance(ref self: ContractState, pool_member: ContractAddress, amount: Amount) {
    let trace = self.pool_member_epoch_balance.entry(pool_member);
    let pool_member_balance = PoolMemberBalanceTrait::new(
        balance: amount,
        cumulative_rewards_trace_idx: self.cumulative_rewards_trace_length() + 1,
    );
    trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance);
}
``` [2](#0-1) 

The `insert` function in the trace only merges entries with the same epoch key; balance changes in distinct epochs always append a new checkpoint: [3](#0-2) 

`set_member_balance` is called by every balance-modifying entrypoint available to an unprivileged pool member: `add_to_delegation_pool`, `exit_delegation_pool_intent`, and the incoming side of `switch_delegation_pool`. [4](#0-3) [5](#0-4) 

The `entry_to_claim_from` cursor stored in `pool_member_info` is only advanced inside `claim_rewards`, so all trace entries accumulated since the last successful claim must be re-iterated on the next call: [6](#0-5) 

Each loop iteration performs at least two storage reads (one `pool_member_trace.at(...)` and one `find_sigma` call that reads `cumulative_rewards_trace`). On Starknet, storage reads are among the most gas-expensive operations. A sufficiently long trace will exhaust the transaction gas limit, causing `claim_rewards` to revert every time it is called.

---

### Impact Explanation

When `claim_rewards` reverts due to OOG, the pool member's accumulated yield is permanently frozen: the cursor `entry_to_claim_from` is never advanced, so every subsequent call re-enters the same oversized loop and reverts again. There is no alternative path to withdraw the yield. This constitutes **permanent freezing of unclaimed yield**, which is an explicitly listed High impact.

---

### Likelihood Explanation

The attack requires no privileged access. Any pool member can trigger it by:

1. Delegating to a pool.
2. Calling `add_to_delegation_pool` (or `exit_delegation_pool_intent`) once per epoch across many epochs, without ever calling `claim_rewards`.
3. After accumulating enough trace entries, calling `claim_rewards` causes OOG.

The minimum number of epochs required depends on Starknet's per-transaction gas limit and the cost per storage read. Given that each iteration involves multiple storage reads, a few hundred epochs of balance changes (achievable over months in a live protocol) is sufficient to trigger the condition. The protocol itself has no cap on the number of balance changes a member can make, and no mechanism that forces reward claims before balance updates.

---

### Recommendation

1. **Require a reward claim before any balance change**: force `claim_rewards` to be called (or inline the reward settlement) inside `add_to_delegation_pool` and `exit_delegation_pool_intent`, keeping `entry_to_claim_from` always at the current trace tail.
2. **Alternatively, paginate `claim_rewards`**: accept a `max_iterations` parameter so a member can drain the backlog over multiple transactions.
3. **Cap the number of unclaimed balance-change epochs**: revert `add_to_delegation_pool` / `exit_delegation_pool_intent` if `pool_member_trace_length - entry_to_claim_from` exceeds a safe bound (e.g., 200).

---

### Proof of Concept

```
1. Staker stakes and opens a delegation pool.
2. Delegator calls `enter_delegation_pool` in epoch E₀.
3. For epochs E₁ … E₀+N (N = 500, for example):
   a. Advance to the next epoch.
   b. Delegator calls `add_to_delegation_pool(1)` — appends one new entry to
      `pool_member_epoch_balance` at epoch (current + K).
   c. Delegator does NOT call `claim_rewards`.
4. After N epochs, delegator calls `claim_rewards`.
   → `calculate_rewards` enters the while-loop with `pool_member_trace_length ≈ N`.
   → Each iteration reads storage twice (trace entry + cumulative_rewards_trace).
   → Transaction runs out of gas; delegator's yield is permanently frozen.
```

The codebase itself acknowledges the risk with the comment: *"This loop is unbounded but unlikely to exceed gas limits"* — but provides no enforcement mechanism to keep it bounded. [7](#0-6)

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

**File:** src/pool/pool.cairo (L348-359)
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
