### Title
Unbounded Loop in `calculate_rewards` Enables Permanent Freezing of Pool Member Unclaimed Yield - (File: src/pool/pool.cairo)

### Summary

The `calculate_rewards` function in `Pool` iterates over a pool member's entire `pool_member_epoch_balance` trace in an unbounded loop. Because any pool member can grow this trace by one entry per epoch at minimal cost (1 wei per `add_to_delegation_pool` call), a pool member who defers claiming rewards across many epochs will eventually make `claim_rewards` exceed the Starknet transaction gas limit, permanently freezing their unclaimed yield.

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` contains an explicitly acknowledged unbounded loop:

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
``` [1](#0-0) 

The loop iterates over `pool_member_epoch_balance`, a `Vec`-backed trace. Each entry is appended by `set_member_balance`, which inserts at key `current_epoch + K`:

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

The underlying `insert` only appends a new checkpoint when the key differs from the last entry's key; otherwise it overwrites. Since the key is `epoch + K`, one new entry is appended per epoch in which a balance-changing operation occurs. [3](#0-2) 

`set_member_balance` is called from three public entry points:
- `enter_delegation_pool` (line 201)
- `add_to_delegation_pool` via `increase_member_balance` (line 242)
- `exit_delegation_pool_intent` (line 278) [4](#0-3) [5](#0-4) [6](#0-5) 

`add_to_delegation_pool` enforces only `amount.is_non_zero()` — there is no minimum delegation amount:

```cairo
assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
``` [7](#0-6) 

`claim_rewards` calls `calculate_rewards` with `entry_to_claim_from` set to the value stored in `pool_member_info`, which is only advanced when a successful `claim_rewards` completes:

```cairo
let (mut rewards, updated_entry_to_claim_from) = self
    .calculate_rewards(
        :pool_member,
        from_checkpoint: pool_member_info.reward_checkpoint,
        :until_checkpoint,
        entry_to_claim_from: pool_member_info.entry_to_claim_from,
    );
``` [8](#0-7) 

If `claim_rewards` never completes (runs out of gas), `entry_to_claim_from` is never updated, so every subsequent call must re-iterate the same growing trace from the same starting index.

### Impact Explanation

A pool member who calls `add_to_delegation_pool` with 1 wei once per epoch, without ever claiming rewards, accumulates one new trace entry per epoch. After enough epochs the `calculate_rewards` loop — which performs multiple storage reads per iteration (`pool_member_trace.at(...)` and `find_sigma(...)`) — will exceed the Starknet per-transaction gas limit. Once that threshold is crossed, every future call to `claim_rewards` for that pool member reverts out-of-gas. Because `entry_to_claim_from` is only persisted on a successful completion, the state is permanently stuck: **the pool member's accumulated unclaimed yield is frozen forever with no recovery path**.

This matches the allowed impact: **Permanent freezing of unclaimed yield (High)**.

### Likelihood Explanation

- The minimum cost per epoch is 1 wei of the pool token plus Starknet gas (significantly cheaper than Ethereum L1).
- No privileged role is required; any pool member can execute this.
- The trace grows monotonically and is never pruned; there is no protocol mechanism to reset or compact it.
- The developers themselves acknowledge the loop is unbounded (the comment on line 858 reads "This loop is unbounded but unlikely to exceed gas limits"), confirming awareness of the risk but no mitigation.
- On Starknet, where gas costs are lower and epochs may be short, the number of epochs required to reach the gas limit is reachable over a realistic protocol lifetime.

Likelihood: **Medium** (requires sustained multi-epoch preparation but is permissionless and low-cost).

### Recommendation

1. **Short term**: Enforce a minimum delegation amount (e.g., `STRK_CONFIG.min_for_rewards = 10^18`) for `add_to_delegation_pool` and `enter_delegation_pool`, raising the per-epoch cost of trace inflation to a level that makes the attack economically impractical.
2. **Short term**: Add a maximum bound on the number of loop iterations in `calculate_rewards` and allow partial reward claims, storing the updated `entry_to_claim_from` even when only a portion of the trace is processed.
3. **Long term**: Introduce periodic trace compaction or a "checkpoint claim" mechanism so that the trace length is bounded by the number of unclaimed epochs rather than the total lifetime of the pool member.

### Proof of Concept

1. Pool member Eve enters a STRK delegation pool with 1 wei: `enter_delegation_pool(reward_address, 1)`.
2. Each epoch, Eve calls `add_to_delegation_pool(eve_address, 1)`. Each call in a new epoch appends one entry to `pool_member_epoch_balance[eve_address]` via `set_member_balance` → `trace.insert(key: epoch + K, ...)`.
3. Eve never calls `claim_rewards`, so `entry_to_claim_from` remains at 0.
4. After N epochs the trace has N entries. When `claim_rewards` is called, `calculate_rewards` loops N times, each iteration executing `pool_member_trace.at(i)` (storage read) and `find_sigma(...)` (additional storage reads).
5. Once N is large enough to exhaust the Starknet transaction gas budget, every call to `claim_rewards(eve_address)` reverts. `entry_to_claim_from` is never updated. Eve's accumulated yield is permanently inaccessible. [9](#0-8) [10](#0-9)

### Citations

**File:** src/pool/pool.cairo (L201-201)
```text
            self.set_member_balance(:pool_member, :amount);
```

**File:** src/pool/pool.cairo (L233-233)
```text
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
```

**File:** src/pool/pool.cairo (L242-242)
```text
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
```

**File:** src/pool/pool.cairo (L278-278)
```text
            self.set_member_balance(:pool_member, amount: new_delegated_stake);
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

**File:** src/pool/pool.cairo (L857-888)
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
