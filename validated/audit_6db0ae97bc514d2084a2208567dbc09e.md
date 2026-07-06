### Title
Unbounded `pool_member_epoch_balance` Trace Causes Permanent Freezing of Unclaimed Pool Rewards - (File: `src/pool/pool.cairo`)

### Summary
The `calculate_rewards` function in `src/pool/pool.cairo` iterates over every entry in a pool member's `pool_member_epoch_balance` trace since their last claim checkpoint. This trace grows by one entry per epoch in which the pool member makes a balance change (`add_to_delegation_pool`, `exit_delegation_pool_intent`). There is no cap on trace length and no pagination mechanism. A pool member who makes balance changes across sufficiently many epochs without claiming will eventually find their `claim_rewards` call permanently reverting due to gas exhaustion, freezing their unclaimed yield forever.

### Finding Description

**Root cause — acknowledged unbounded loop in `calculate_rewards`:**

`src/pool/pool.cairo` lines 857–877 contain an explicit developer acknowledgment:

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

Each iteration performs at minimum one `pool_member_trace.at(...)` storage read and one `find_sigma(...)` call (which itself reads from `cumulative_rewards_trace`). The number of iterations equals the number of balance-change epochs since the last claim.

**How the trace grows:**

`set_member_balance` (line 728) inserts a new checkpoint keyed by `get_epoch_plus_k()` = `current_epoch + K`:

```cairo
fn set_member_balance(ref self: ContractState, pool_member: ContractAddress, amount: Amount) {
    let trace = self.pool_member_epoch_balance.entry(pool_member);
    let pool_member_balance = PoolMemberBalanceTrait::new(
        balance: amount,
        cumulative_rewards_trace_idx: self.cumulative_rewards_trace_length() + 1,
    );
    trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance);
}
```

The `insert` logic in `trace.cairo` lines 163–173 only updates the last entry if the key matches; otherwise it **appends a new checkpoint**. Therefore, each epoch in which a balance change occurs adds exactly one new entry to the trace.

`set_member_balance` / `increase_member_balance` is called from:
- `add_to_delegation_pool` (line 242) — callable by any pool member or their reward address
- `exit_delegation_pool_intent` (line 278) — callable by any pool member

**No pagination or cap exists.** The `entry_to_claim_from` cursor is stored per pool member and advanced after each successful `claim_rewards`, but if the trace grows large enough that a single `claim_rewards` call exceeds the block gas limit, the cursor can never advance and the member is permanently locked out.

### Impact Explanation

**Impact: High — Permanent freezing of unclaimed yield.**

Once the `pool_member_epoch_balance` trace for a pool member grows large enough that the `calculate_rewards` loop exceeds Starknet's per-transaction gas/step limit, every subsequent call to `claim_rewards` for that member will revert. Because there is no alternative entry point to claim rewards in smaller batches, and because `entry_to_claim_from` can only advance inside a successful `claim_rewards` execution, the pool member's accumulated STRK rewards are permanently unclaimable. The funds remain locked in the pool contract with no recovery path.

### Likelihood Explanation

**Likelihood: Medium.**

A pool member who actively manages their delegation — adding or partially exiting across many epochs — will naturally accumulate trace entries. The protocol is designed for long-term participation spanning hundreds or thousands of epochs. A member who makes one balance change per epoch and claims rewards infrequently (e.g., once a year) could accumulate hundreds of entries. Each iteration of the loop performs multiple storage reads plus a `find_sigma` call, making the per-iteration cost non-trivial. No privileged access is required; any pool member can reach this state through normal protocol usage.

### Recommendation

1. **Introduce a maximum iteration cap** inside `calculate_rewards` and allow partial reward claims, storing the advanced `entry_to_claim_from` even when the full range is not processed in one call.
2. **Expose a paginated `claim_rewards` variant** that accepts a `max_entries` parameter, allowing callers to process the trace in multiple transactions.
3. **Enforce a maximum trace length** per pool member by requiring a `claim_rewards` call before any balance change that would push the unclaimed trace window beyond a safe threshold (e.g., 200 entries).

### Proof of Concept

```
1. Pool member Alice enters the delegation pool in epoch E₀.
2. Every epoch thereafter, Alice calls add_to_delegation_pool(amount: 1)
   → each call in a new epoch appends one entry to pool_member_epoch_balance[Alice].
3. Alice never calls claim_rewards.
4. After N epochs (e.g., N = 500), Alice calls claim_rewards.
5. calculate_rewards iterates from entry_to_claim_from=0 to pool_member_trace_length=N.
   Each iteration: one storage read (pool_member_trace.at) + one find_sigma call
   (reading cumulative_rewards_trace).
6. At sufficiently large N, the transaction exceeds the Starknet step/gas limit and reverts.
7. entry_to_claim_from remains 0. Every future claim_rewards call also reverts.
8. Alice's accumulated STRK rewards are permanently frozen in the pool contract.
```

The developer comment at `src/pool/pool.cairo` line 858 — *"This loop is unbounded but unlikely to exceed gas limits"* — confirms awareness of the issue but relies on an optimistic assumption that does not hold for long-lived, actively-managed delegations. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** src/pool/pool.cairo (L221-254)
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
        }
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
