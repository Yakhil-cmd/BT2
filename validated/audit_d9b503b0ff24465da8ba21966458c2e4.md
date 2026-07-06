### Title
Unbounded Loop in `calculate_rewards` Enables Permanent Freezing of Unclaimed Yield via Trace Inflation - (File: src/pool/pool.cairo)

### Summary
The `calculate_rewards` function in `src/pool/pool.cairo` contains an unbounded loop that iterates over every balance-change checkpoint in a pool member's `pool_member_epoch_balance` trace. Because the trace grows by one entry per epoch in which the member makes a balance change, a pool member who repeatedly calls `add_to_delegation_pool` across many epochs without claiming rewards will eventually cause `claim_rewards` to exceed the Starknet transaction gas limit, permanently freezing their unclaimed yield. The developers themselves acknowledge the risk in a code comment: *"This loop is unbounded but unlikely to exceed gas limits."*

### Finding Description

**Root cause — unbounded loop in `calculate_rewards`:**

`calculate_rewards` iterates from `entry_to_claim_from` up to `pool_member_trace_length`, processing every balance-change checkpoint that falls before `until_epoch`. Each iteration performs at least two storage reads: one via `pool_member_trace.at(entry_to_claim_from)` and one via `find_sigma(pool_member_checkpoint, ...)`. There is no cap on the number of iterations. [1](#0-0) 

**How the trace grows:**

`set_member_balance` inserts a new checkpoint keyed at `current_epoch + K`. The underlying `insert` function only appends a new entry when the key differs from the last entry's key — meaning one new entry is appended per epoch in which a balance change occurs. [2](#0-1) [3](#0-2) 

**Entry points that grow the trace:**

- `enter_delegation_pool` calls `set_member_balance` directly.
- `add_to_delegation_pool` calls `increase_member_balance` → `set_member_balance`.
- `exit_delegation_pool_intent` also calls `set_member_balance`. [4](#0-3) 

**`claim_rewards` is the trigger:**

`claim_rewards` calls `calculate_rewards` with the stored `entry_to_claim_from`. After a successful claim, `entry_to_claim_from` advances to the new position. If the member never claims (or claims infrequently), the loop must process all accumulated entries in a single transaction. [5](#0-4) 

**Exploit path:**

1. Pool member calls `enter_delegation_pool` (trace length = 1).
2. Each epoch, pool member calls `add_to_delegation_pool` with the minimum non-zero amount (1 unit). Each call in a new epoch appends one entry to the trace.
3. Pool member never calls `claim_rewards`, so `entry_to_claim_from` stays at 0.
4. After N epochs of balance changes, the trace has N entries.
5. When `claim_rewards` is eventually called (by the pool member or their reward address), the loop must iterate over all N entries, each requiring multiple storage reads. Once N is large enough, the transaction exceeds the Starknet gas limit and reverts.
6. Because `entry_to_claim_from` is only updated on a successful `claim_rewards`, and every future attempt also reverts, the unclaimed yield is permanently frozen.

The principal is still recoverable via `exit_delegation_pool_intent` / `exit_delegation_pool_action` (neither calls `calculate_rewards`), but all accumulated rewards are permanently inaccessible.

### Impact Explanation

**Permanent freezing of unclaimed yield (High / Medium).** Once the trace grows beyond the gas-limit threshold, every call to `claim_rewards` reverts. The pool member's accumulated STRK rewards are locked in the contract forever with no recovery path, because `claim_rewards` is the only function that transfers rewards and advances `entry_to_claim_from`. [6](#0-5) 

### Likelihood Explanation

The protocol is designed to run indefinitely. A pool member who makes one balance change per epoch — a normal, incentivized behavior (e.g., compounding by re-delegating rewards) — will accumulate one trace entry per epoch. The minimum cost per epoch is 1 token unit plus gas. Over hundreds of epochs (months of operation), the trace grows large enough to approach or exceed the Starknet per-transaction gas ceiling. The developers explicitly noted the risk in the source code, confirming awareness but no mitigation. [7](#0-6) 

### Recommendation

1. **Checkpoint-based pagination:** Store `entry_to_claim_from` and allow `claim_rewards` to process only a bounded number of entries per call (e.g., a configurable `max_entries` parameter), returning partial rewards and updating the checkpoint so subsequent calls continue from where the previous one stopped.
2. **Enforce regular claiming:** Require or incentivize pool members to claim rewards at least once per epoch, keeping the unclaimed window small.
3. **Trace compaction:** After a successful `claim_rewards`, compact already-processed entries from the trace to prevent unbounded growth.

### Proof of Concept

```
Epoch 0:  pool_member calls enter_delegation_pool(amount=MIN)
          → trace = [(epoch=K, balance=MIN)]  length=1

Epoch 1:  pool_member calls add_to_delegation_pool(amount=1)
          → trace = [(epoch=K, ...), (epoch=1+K, ...)]  length=2

Epoch 2:  pool_member calls add_to_delegation_pool(amount=1)
          → trace length=3

... (repeat for N epochs, never calling claim_rewards) ...

Epoch N:  pool_member calls claim_rewards
          → calculate_rewards loops from entry_to_claim_from=0
            to pool_member_trace_length=N
          → each iteration: storage read (at) + storage read (find_sigma)
          → at N ≈ gas_limit / cost_per_iteration, transaction OOG-reverts
          → entry_to_claim_from remains 0; all future claim_rewards also revert
          → unclaimed yield permanently frozen
``` [8](#0-7) [9](#0-8)

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

**File:** src/pool/pool.cairo (L844-877)
```text
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
