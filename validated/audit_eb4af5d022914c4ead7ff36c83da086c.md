### Title
Unbounded Loop in `calculate_rewards` Allows Permanent Freezing of Pool Member Unclaimed Yield - (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` internal function in the `Pool` contract contains an unbounded `while` loop that iterates over every entry in a pool member's `pool_member_epoch_balance` trace. Because any balance-changing operation (`add_to_delegation_pool`, `exit_delegation_pool_intent`, `enter_delegation_pool`) appends a new entry to this trace for each distinct epoch, a long-lived delegator who changes their balance across many epochs will accumulate an arbitrarily large trace. When `claim_rewards` is eventually called, the loop iterates over all accumulated entries and can exceed Starknet's per-transaction gas limit, permanently bricking the member's ability to claim their yield.

The code itself acknowledges the issue with the comment: *"This loop is unbounded but unlikely to exceed gas limits."*

---

### Finding Description

**Root cause — `calculate_rewards` loop (`src/pool/pool.cairo`, lines 857–877):**

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
    ...
    entry_to_claim_from += 1;
}
```

The loop bound is `pool_member_trace_length`, which is the total number of entries ever written to `pool_member_epoch_balance` for that member. Each iteration also calls `find_sigma`, which performs additional storage reads, making each iteration non-trivial in gas cost.

**How the trace grows — `set_member_balance` (`src/pool/pool.cairo`, lines 718–729):**

```cairo
fn set_member_balance(ref self: ContractState, pool_member: ContractAddress, amount: Amount) {
    let trace = self.pool_member_epoch_balance.entry(pool_member);
    let pool_member_balance = PoolMemberBalanceTrait::new(...);
    trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance);
}
```

`set_member_balance` is called by every balance-changing public entry point:
- `enter_delegation_pool` → `set_member_balance` (line 201)
- `add_to_delegation_pool` → `increase_member_balance` → `set_member_balance` (lines 242, 738)
- `exit_delegation_pool_intent` → `set_member_balance` (line 278)

The key used is `current_epoch + K`. Because `K` is a fixed constant, each call in a **different epoch** inserts a new distinct key into the trace. Multiple calls within the same epoch overwrite the same key and do not grow the trace. Therefore, the trace length grows by at most 1 per epoch in which the member changes their balance.

**How `claim_rewards` triggers the loop — (`src/pool/pool.cairo`, lines 335–377):**

```cairo
fn claim_rewards(ref self: ContractState, pool_member: ContractAddress) -> Amount {
    ...
    let (mut rewards, updated_entry_to_claim_from) = self
        .calculate_rewards(
            :pool_member,
            from_checkpoint: pool_member_info.reward_checkpoint,
            :until_checkpoint,
            entry_to_claim_from: pool_member_info.entry_to_claim_from,
        );
    ...
}
```

`entry_to_claim_from` is a persisted cursor that advances with each successful `claim_rewards` call. If a member never claims (or claims infrequently), the cursor falls far behind the trace length, and the next `claim_rewards` must iterate over all unclaimed entries in one transaction.

---

### Impact Explanation

A pool member who has been active for a large number of epochs without claiming rewards will have a `pool_member_epoch_balance` trace with one entry per epoch of balance change. When `claim_rewards` is called, the loop must process all of those entries in a single transaction. Once the trace is large enough, the transaction will always revert due to gas exhaustion, and the member's accumulated yield is permanently frozen — there is no partial-claim mechanism and no way to advance `entry_to_claim_from` without a successful `claim_rewards` call.

**Impact: Permanent freezing of unclaimed yield** (matches allowed High impact).

---

### Likelihood Explanation

Any pool member who:
1. Regularly changes their delegated balance (via `add_to_delegation_pool` or `exit_delegation_pool_intent`) across many epochs, **and**
2. Does not call `claim_rewards` frequently enough to keep the cursor close to the trace head

will eventually reach the gas limit. Given that epochs are protocol-defined time windows and the protocol is designed for long-term participation, a member active for hundreds of epochs with periodic balance changes is a realistic scenario. The member does not need to act maliciously — this can happen organically to any long-lived delegator.

---

### Recommendation

1. **Introduce a partial-claim mechanism**: Allow `claim_rewards` to accept an optional `max_iterations` parameter, processing only up to that many trace entries per call and persisting the updated `entry_to_claim_from` cursor even on a partial run.
2. **Alternatively, cap the loop**: Enforce a hard maximum number of iterations per `claim_rewards` call and return partial rewards, requiring multiple calls to fully drain accumulated rewards.
3. **Prune the trace on claim**: After processing entries up to `entry_to_claim_from`, consider removing or compacting those entries so the trace does not grow without bound.

---

### Proof of Concept

1. Delegator calls `enter_delegation_pool` in epoch 1 → trace length = 1.
2. Delegator calls `add_to_delegation_pool` once per epoch for epochs 2 through N → trace length = N.
3. Delegator never calls `claim_rewards` during this period.
4. In epoch N+1, delegator calls `claim_rewards`.
5. `calculate_rewards` enters the `while` loop and iterates N times, each iteration calling `find_sigma` (storage reads) and `compute_rewards_rounded_down`.
6. For sufficiently large N (e.g., N ≈ several hundred depending on Starknet's gas limit per transaction), the transaction reverts with out-of-gas.
7. All subsequent calls to `claim_rewards` also revert — the cursor `entry_to_claim_from` is never advanced, and the yield is permanently frozen. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** src/pool/pool.cairo (L335-360)
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
