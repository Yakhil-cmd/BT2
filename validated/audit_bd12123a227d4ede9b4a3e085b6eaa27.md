### Title
Unbounded Loop in `calculate_rewards` Over Growing `pool_member_epoch_balance` Trace Can Permanently Freeze Delegator Rewards - (File: src/pool/pool.cairo)

### Summary
The `calculate_rewards` function in `src/pool/pool.cairo` iterates over a per-pool-member balance trace (`pool_member_epoch_balance`) in an unbounded loop. Each balance-modifying action by a pool member in a distinct epoch appends a new entry to this trace. If a pool member accumulates enough entries without claiming rewards, the `claim_rewards` call will exceed the Starknet gas limit, permanently freezing their unclaimed yield with no recovery path.

### Finding Description

The `calculate_rewards` internal function contains an unbounded `while` loop:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch {
        break;
    }
    let to_sigma = self.find_sigma(pool_member_checkpoint, curr_epoch: until_epoch);
    // ...
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

The trace grows via `set_member_balance`, which calls `trace.insert(key: self.get_epoch_plus_k(), value: ...)`. The `insert` function in `trace.cairo` only updates the last entry in-place if the key (epoch) matches; otherwise it **appends a new checkpoint**:

```cairo
if last.key == key {
    last.value = value;
    checkpoints[len - 1].write(last);
} else {
    assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
``` [2](#0-1) 

`set_member_balance` is called by `increase_member_balance`, which is called by `add_to_delegation_pool` and `enter_delegation_pool_from_staking_contract`. It is also called directly by `exit_delegation_pool_intent`: [3](#0-2) [4](#0-3) 

Each call to `add_to_delegation_pool` or `exit_delegation_pool_intent` in a **different epoch** appends one new entry to the trace. The `entry_to_claim_from` cursor stored in `pool_member_info` is only advanced on a **successful** `claim_rewards` call:

```cairo
pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
``` [5](#0-4) 

If the trace grows large enough that `claim_rewards` OOGs before completing, `entry_to_claim_from` is never updated, and there is no mechanism to process the trace in smaller batches. The rewards are permanently frozen.

The `pool_member_info_v1` view function also calls `calculate_rewards` unconditionally without updating the cursor, meaning it too will OOG for large traces: [6](#0-5) 

### Impact Explanation

A pool member whose `pool_member_epoch_balance` trace grows beyond the processable size in a single transaction will have their unclaimed STRK rewards permanently frozen. The `claim_rewards` function is the only path to retrieve rewards, and it has no partial-processing mechanism. This matches the allowed impact: **Permanent freezing of unclaimed yield (High)** and **Unbounded gas consumption (Medium)**.

### Likelihood Explanation

Each balance-modifying action in a distinct epoch appends one entry. A pool member who:
- Calls `add_to_delegation_pool` or `exit_delegation_pool_intent` once per epoch (a normal usage pattern), AND
- Does not call `claim_rewards` for an extended period (e.g., hundreds of epochs)

will accumulate a trace large enough to OOG. Additionally, the reward address of a pool member is permitted to call `add_to_delegation_pool` on their behalf: [7](#0-6) 

A malicious or compromised reward address can therefore deliberately inflate the trace by calling `add_to_delegation_pool` with 1 wei each epoch, causing the pool member's `claim_rewards` to permanently OOG. The developers themselves acknowledge the risk in a code comment: *"This loop is unbounded but unlikely to exceed gas limits."* [8](#0-7) 

### Recommendation

1. **Paginated claiming**: Add a `claim_rewards_partial(max_entries: u64)` variant that processes at most `max_entries` trace entries per call and persists the updated `entry_to_claim_from`, allowing recovery from an oversized trace.
2. **Trace compaction**: After a successful `claim_rewards`, compact or prune already-processed entries from the trace so the cursor never needs to re-scan them.
3. **Minimum balance-change interval**: Enforce a minimum amount per `add_to_delegation_pool` call to make trace-inflation attacks economically infeasible.

### Proof of Concept

1. Pool member `A` delegates to a pool.
2. Each epoch, `A` (or their reward address) calls `add_to_delegation_pool` with 1 wei. Each call in a new epoch appends one entry to `pool_member_epoch_balance` via `set_member_balance` → `trace.insert`.
3. After `N` epochs without claiming, the trace has `N` entries.
4. `A` calls `claim_rewards`. The `calculate_rewards` loop iterates from `entry_to_claim_from = 0` to `N`, calling `find_sigma` (a storage read) on each iteration.
5. For sufficiently large `N`, the transaction exceeds the Starknet gas limit and reverts.
6. Because the revert prevents `entry_to_claim_from` from being updated, every subsequent `claim_rewards` call also OOGs. `A`'s accumulated STRK rewards are permanently frozen. [9](#0-8) [10](#0-9)

### Citations

**File:** src/pool/pool.cairo (L256-278)
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
```

**File:** src/pool/pool.cairo (L335-344)
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
```

**File:** src/pool/pool.cairo (L354-359)
```text
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
            rewards += pool_member_info._unclaimed_rewards_from_v0;
            pool_member_info._unclaimed_rewards_from_v0 = Zero::zero();
            pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
            pool_member_info.reward_checkpoint = until_checkpoint;
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

**File:** src/pool/pool.cairo (L837-888)
```text
        fn calculate_rewards(
            self: @ContractState,
            pool_member: ContractAddress,
            from_checkpoint: PoolMemberCheckpoint,
            until_checkpoint: PoolMemberCheckpoint,
            mut entry_to_claim_from: VecIndex,
        ) -> (Amount, VecIndex) {
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

            // Compute the remaining rewards from (inclusive) the last visited balance change in
            // `pool_member_trace` (or from `from_checkpoint`) to (exclusive) `until_checkpoint`.
            let to_sigma = self.find_sigma(until_checkpoint, curr_epoch: until_epoch);
            rewards +=
                compute_rewards_rounded_down(
                    amount: from_balance, interest: to_sigma - from_sigma, :base_value,
                );

            (rewards, entry_to_claim_from)
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
