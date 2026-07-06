### Title
Unbounded Loop in `calculate_rewards` Over Delegator Balance Trace Enables Permanent Freezing of Unclaimed Yield - (File: src/pool/pool.cairo)

---

### Summary

The `calculate_rewards` function in `src/pool/pool.cairo` iterates over the entire `pool_member_epoch_balance` trace without any upper bound. A pool member (or their reward address) can grow this trace arbitrarily by calling `add_to_delegation_pool` with a minimal amount across many distinct epochs. Once the trace is large enough, every subsequent `claim_rewards` call will exceed the Starknet per-transaction gas limit, permanently freezing the pool member's unclaimed yield.

---

### Finding Description

`calculate_rewards` (lines 837–888 of `src/pool/pool.cairo`) contains a `while` loop that iterates over every entry in `pool_member_epoch_balance` from `entry_to_claim_from` up to `pool_member_trace_length`:

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
```

The comment itself acknowledges the loop is unbounded. Each iteration performs multiple storage reads (`pool_member_trace.at`, `find_sigma` → `cumulative_rewards_trace_vec.at`), making it gas-heavy.

The trace grows via `set_member_balance` → `trace.insert`:

```cairo
fn set_member_balance(ref self: ContractState, pool_member: ContractAddress, amount: Amount) {
    let trace = self.pool_member_epoch_balance.entry(pool_member);
    let pool_member_balance = PoolMemberBalanceTrait::new(...);
    trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance);
}
```

The `insert` function in `src/pool/pool_member_balance_trace/trace.cairo` (lines 152–175) only deduplicates if the last key equals the new key. Since the key is `current_epoch + K`, each call in a **different epoch** appends a new checkpoint. Both `add_to_delegation_pool` and `exit_delegation_pool_intent` call `set_member_balance`, so each invocation in a new epoch grows the trace by one entry.

`add_to_delegation_pool` only requires `amount > 0` — there is no minimum beyond non-zero:

```cairo
assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
```

`claim_rewards` (lines 335–377) calls `calculate_rewards` unconditionally, passing the full trace range. There is no pagination, partial-claim, or iteration cap.

---

### Impact Explanation

Once the `pool_member_epoch_balance` trace for a given pool member grows large enough, every call to `claim_rewards` for that member will exceed the Starknet per-transaction gas limit and revert. The pool member's accrued yield becomes permanently inaccessible — it cannot be claimed, and there is no alternative code path to retrieve it. This matches the allowed impact: **Permanent freezing of unclaimed yield (High)**.

---

### Likelihood Explanation

The only precondition is being a pool member (or the pool member's reward address). The minimum cost per trace entry is 1 token unit plus gas. An attacker who is the reward address of a victim can call `add_to_delegation_pool` with `amount = 1` once per epoch to inflate the victim's trace. Even a legitimate user who frequently tops up their delegation across many epochs will accumulate entries organically. Given that epochs are time-bounded, reaching a problematic trace size takes sustained effort, but there is no protocol-level defense preventing it.

---

### Recommendation

1. **Cap the loop**: Introduce a `max_iterations` parameter to `claim_rewards` (analogous to the `maxProcessCount` fix described in the reference report), allowing partial reward claims across multiple transactions.
2. **Compact the trace**: After a successful `claim_rewards`, truncate or compact already-processed entries from the trace so `entry_to_claim_from` advances and old entries are not re-iterated.
3. **Enforce a minimum deposit size**: Raise the minimum `amount` for `add_to_delegation_pool` to a value that makes trace inflation economically infeasible.

---

### Proof of Concept

1. Pool member Alice delegates a small amount to a pool.
2. Alice (or her reward address) calls `add_to_delegation_pool(pool_member: alice, amount: 1)` once per epoch for N epochs. Each call appends one entry to `pool_member_epoch_balance` because the epoch key (`current_epoch + K`) differs each time.
3. After N epochs, `pool_member_epoch_balance.length()` for Alice equals N + 1 (initial entry + N additions).
4. Alice calls `claim_rewards`. `calculate_rewards` enters the `while` loop and iterates N times, each iteration reading from `pool_member_epoch_balance` and calling `find_sigma` (which reads from `cumulative_rewards_trace_vec`). For sufficiently large N, the transaction runs out of gas and reverts.
5. Every future `claim_rewards` call for Alice also reverts. Alice's unclaimed yield is permanently frozen.

**Key code references:**

- Unbounded loop: [1](#0-0) 
- Trace growth via `set_member_balance`: [2](#0-1) 
- `insert` appends new checkpoint per distinct epoch: [3](#0-2) 
- `add_to_delegation_pool` — only `amount > 0` required: [4](#0-3) 
- `claim_rewards` calls `calculate_rewards` unconditionally: [5](#0-4)

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
