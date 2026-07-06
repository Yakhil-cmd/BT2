### Title
Unbounded Loop in `calculate_rewards` Enables Permanent Freezing of Pool Member Unclaimed Yield - (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` internal function in `Pool` contains an explicitly acknowledged unbounded loop that iterates over every entry in a pool member's `pool_member_epoch_balance` trace. Because any pool member can grow this trace without limit by repeatedly changing their delegation balance across epochs, a sufficiently large trace will cause every future `claim_rewards` call for that member to exceed Starknet's per-transaction gas limit, permanently freezing their unclaimed yield.

---

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` iterates over the entire `pool_member_epoch_balance` trace for a given pool member, starting from `entry_to_claim_from`:

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

The trace grows by one entry per epoch whenever the pool member calls `add_to_delegation_pool` or `exit_delegation_pool_intent`, because `set_member_balance` calls `trace.insert(key: self.get_epoch_plus_k(), value: ...)`, and the `insert` implementation only merges entries with the same epoch key — a new epoch always appends a new checkpoint.

The `entry_to_claim_from` cursor stored in `pool_member_info` means that regular claimers only process new entries. However, a pool member who accumulates many balance changes across many epochs without claiming will eventually face a single `claim_rewards` call that must iterate over all of them. Once the trace is large enough to exceed the Starknet transaction gas limit, `claim_rewards` will always revert, permanently freezing the member's yield.

Inside the loop, each iteration also calls `find_sigma`, which reads from the `cumulative_rewards_trace` storage vector, adding further per-iteration cost.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Once the `pool_member_epoch_balance` trace for a given pool member grows beyond the gas budget of a single Starknet transaction, neither the pool member nor their `reward_address` can ever successfully call `claim_rewards` for that member. All accrued rewards are permanently locked in the pool contract with no recovery path, because there is no partial-claim or pagination mechanism.

---

### Likelihood Explanation

**Medium.**

A pool member can grow their trace by one entry per epoch by alternating `add_to_delegation_pool` and `exit_delegation_pool_intent` calls. Starknet epochs are short (on the order of hours), so over months of activity a trace of thousands of entries is realistic. The pool member need not claim rewards during this period. The code itself acknowledges the risk with the comment *"This loop is unbounded but unlikely to exceed gas limits"*, confirming the developers are aware of the theoretical bound but have not enforced one. No privileged role is required; any pool member can trigger this condition on their own account.

---

### Recommendation

1. **Short term**: Introduce a `max_entries_per_claim` parameter and process only that many trace entries per `claim_rewards` call, advancing `entry_to_claim_from` and returning partial rewards. Callers can invoke `claim_rewards` multiple times to drain the full backlog.
2. **Long term**: Cap the number of balance-change entries that can be appended to a single pool member's trace per epoch (e.g., enforce that `set_member_balance` is a no-op if the last entry already belongs to the current `epoch + K`), preventing unbounded trace growth entirely.

---

### Proof of Concept

1. Pool member Alice calls `enter_delegation_pool` in epoch 1 → trace length = 1.
2. In each subsequent epoch `e`, Alice calls `add_to_delegation_pool` (minimum amount) then `exit_delegation_pool_intent` (same amount) → one new trace entry per epoch.
3. After `N` epochs without claiming, Alice's `pool_member_epoch_balance` trace has `N` entries and `entry_to_claim_from = 0`.
4. Alice (or her `reward_address`) calls `claim_rewards`. The `calculate_rewards` loop executes `N` iterations, each reading from storage and calling `find_sigma`. For large `N` (e.g., N ≈ 10,000 epochs), the transaction exceeds the Starknet gas limit and reverts.
5. Every subsequent `claim_rewards` attempt also reverts. Alice's accumulated yield is permanently frozen.

**Relevant code locations:**

- Unbounded loop: [1](#0-0) 
- `claim_rewards` entry point that invokes `calculate_rewards`: [2](#0-1) 
- `set_member_balance` / `increase_member_balance` that grow the trace on every balance change: [3](#0-2) 
- `add_to_delegation_pool` (unprivileged entry point that triggers trace growth): [4](#0-3) 
- `exit_delegation_pool_intent` (second unprivileged entry point that triggers trace growth): [5](#0-4)

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

**File:** src/pool/pool.cairo (L718-739)
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

        /// Increase the pool member's balance for the current epoch + K by the given
        /// `amount`.
        /// Returns the previous balance.
        fn increase_member_balance(
            ref self: ContractState, pool_member: ContractAddress, amount: Amount,
        ) -> Amount {
            let current_balance = self.get_last_member_balance(:pool_member);
            self.set_member_balance(:pool_member, amount: current_balance + amount);
            current_balance
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
