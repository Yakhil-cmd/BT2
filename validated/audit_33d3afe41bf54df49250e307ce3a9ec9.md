### Title
Unbounded Loop Over `pool_member_epoch_balance` Trace in `calculate_rewards` Enables Permanent Freezing of Unclaimed Yield - (File: `src/pool/pool.cairo`)

### Summary

The `calculate_rewards` function in `src/pool/pool.cairo` contains an explicitly acknowledged unbounded loop that iterates over every entry in a pool member's `pool_member_epoch_balance` trace since the last claim. Because a pool member can append one new trace entry per epoch by calling `add_to_delegation_pool` or `exit_delegation_pool_intent`, a pool member who accumulates enough entries without claiming will eventually make `claim_rewards` exceed the Starknet block gas limit, permanently freezing their unclaimed yield.

### Finding Description

`calculate_rewards` (lines 837–888) iterates over the entire `pool_member_epoch_balance` trace from `entry_to_claim_from` to `pool_member_trace_length`:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch {
        break;
    }
    let to_sigma = self.find_sigma(pool_member_checkpoint, curr_epoch: until_epoch);
    ...
    entry_to_claim_from += 1;
}
```

Each iteration performs at least one storage read (`pool_member_trace.at`) plus additional storage reads inside `find_sigma` (which reads from `cumulative_rewards_trace`). The cost is O(N) in the number of unclaimed trace entries.

The trace grows via `set_member_balance` (line 728), which calls `trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance)`. The `insert` implementation (lines 152–175 of `src/pool/pool_member_balance_trace/trace.cairo`) appends a new checkpoint only when the key is strictly greater than the last key. Since `get_epoch_plus_k()` returns `current_epoch + K`, each balance change in a distinct epoch appends exactly one new entry.

**Attack path:**

1. Pool member enters the delegation pool.
2. Each epoch, the pool member calls `add_to_delegation_pool` with a minimal amount (1 unit) — this calls `increase_member_balance` → `set_member_balance` → `trace.insert`, appending one new entry per epoch.
3. The pool member never calls `claim_rewards`, so `entry_to_claim_from` stays at 0.
4. After N epochs, the trace has N entries.
5. Any call to `claim_rewards` (or the view function `pool_member_info_v1`) must iterate all N entries.
6. Once N is large enough to exceed the Starknet block gas limit, `claim_rewards` always reverts, permanently freezing the pool member's accumulated unclaimed yield.

The codebase itself acknowledges the risk with the comment: *"This loop is unbounded but unlikely to exceed gas limits."*

### Impact Explanation

When the trace grows beyond the gas budget of a single transaction, `claim_rewards` becomes permanently uncallable for that pool member. All accumulated STRK rewards are frozen in the pool contract and can never be transferred to the reward address. This matches the allowed impact: **Permanent freezing of unclaimed yield (High)**.

Additionally, `pool_member_info_v1` (lines 528–548) is a public view function that also calls `calculate_rewards` without updating `entry_to_claim_from`, meaning every call re-iterates the full trace — this constitutes **unbounded gas consumption (Medium)** for any caller querying the pool member's state.

### Likelihood Explanation

Any pool member can trigger this by calling `add_to_delegation_pool` once per epoch over a sustained period without claiming rewards. The minimum stake required to enter the pool is the only barrier. Given that epochs are protocol-defined time windows and the minimum stake is a fixed threshold, a determined attacker or even an inattentive long-term delegator can accumulate hundreds or thousands of trace entries. Starknet's block gas limit makes this exploitable at a realistic scale.

### Recommendation

1. **Enforce a maximum trace length** per pool member, or require that rewards be claimed before the trace can grow beyond a configurable cap.
2. **Alternatively**, implement a paginated `claim_rewards` that accepts a `max_entries` parameter, allowing partial claims so that the trace can be drained incrementally across multiple transactions.
3. **At minimum**, document the maximum safe trace length and enforce it with an assertion in `set_member_balance` or `calculate_rewards`.

### Proof of Concept

```cairo
// Pseudocode demonstrating trace growth
// Assume epoch_length = 40 blocks, K = 2

// Step 1: Enter pool
pool.enter_delegation_pool(reward_address, amount: MIN_STAKE);
// trace length = 1

// Step 2: Each epoch, add 1 unit to grow the trace
for epoch in 0..N {
    advance_to_next_epoch();
    pool.add_to_delegation_pool(pool_member, amount: 1);
    // trace length grows by 1 each epoch
}
// After N epochs: pool_member_epoch_balance trace length = N + 1
// entry_to_claim_from = 0 (never claimed)

// Step 3: Attempt to claim rewards — iterates N+1 entries
// Each iteration: 1 storage read (trace.at) + find_sigma reads
// At N ~ thousands, gas exceeds Starknet block limit → permanent revert
pool.claim_rewards(pool_member); // OUT OF GAS → unclaimed yield frozen forever
```

**Relevant code locations:**

- Unbounded loop: [1](#0-0) 
- `set_member_balance` appending trace entries: [2](#0-1) 
- `add_to_delegation_pool` triggering trace growth: [3](#0-2) 
- `exit_delegation_pool_intent` triggering trace growth: [4](#0-3) 
- `claim_rewards` calling `calculate_rewards`: [5](#0-4) 
- `pool_member_info_v1` (view) also calling `calculate_rewards`: [6](#0-5) 
- Trace `insert` logic (one entry per distinct epoch key): [7](#0-6)

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

**File:** src/pool/pool.cairo (L256-292)
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
