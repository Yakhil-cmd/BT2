### Title
Unbounded Loop in `calculate_rewards` Allows Permanent Freezing of Delegator's Unclaimed Yield - (File: src/pool/pool.cairo)

### Summary
The `calculate_rewards` function in the Pool contract contains an explicitly acknowledged unbounded `while` loop that iterates over every balance-change checkpoint in a pool member's `pool_member_epoch_balance` trace. A delegator who makes balance changes across many distinct epochs without claiming rewards will accumulate an unbounded number of trace entries. When the trace grows large enough, any call to `claim_rewards` or `pool_member_info_v1` will exceed Starknet's gas limit, permanently freezing the delegator's unclaimed yield.

### Finding Description

Every call to `add_to_delegation_pool` or `exit_delegation_pool_intent` routes through `set_member_balance`, which calls `trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance)`. [1](#0-0) 

The `insert` implementation in the balance trace only **updates** the last checkpoint if the key matches; otherwise it **appends** a new checkpoint: [2](#0-1) 

Because the key is always `current_epoch + K`, each call made in a **different epoch** appends a new entry. A delegator who adjusts their stake once per epoch without ever claiming rewards will accumulate one new checkpoint per epoch, growing the trace without bound.

When `claim_rewards` or `pool_member_info_v1` is called, it invokes `calculate_rewards`, which contains the following loop — **explicitly noted by the developers as unbounded**: [3](#0-2) 

The loop iterates from `entry_to_claim_from` (the index saved at the last successful claim) up to `pool_member_trace_length`, processing every balance-change entry that falls before the current epoch. Each iteration performs a `find_sigma` call, which itself reads from storage. With a sufficiently large trace, the transaction runs out of gas.

`pool_member_info_v1` (a read-only view) also calls `calculate_rewards` directly: [4](#0-3) 

This means even querying the delegator's state becomes impossible once the trace is large enough.

### Impact Explanation

Once the trace is large enough to exceed the gas limit, **no transaction can successfully execute `claim_rewards` for that pool member**. The delegator's accumulated yield is permanently locked in the pool contract with no recovery path, because:

- `claim_rewards` always calls `calculate_rewards` over the full unclaimed range.
- There is no partial-claim mechanism that would allow processing a bounded subset of entries per transaction.
- `entry_to_claim_from` is only advanced on a successful claim; a gas-exhausted transaction reverts, leaving the pointer unchanged.

This matches the allowed impact: **Permanent freezing of unclaimed yield**.

### Likelihood Explanation

The scenario is realistic for any long-term delegator who:
1. Adjusts their stake (via `add_to_delegation_pool` or `exit_delegation_pool_intent`) across many epochs, and
2. Defers claiming rewards for an extended period.

The minimum `amount` for `add_to_delegation_pool` is 1 token unit (only `amount.is_non_zero()` is checked): [5](#0-4) 

A delegator making one balance change per epoch for ~1,000 epochs (a plausible multi-year horizon) would accumulate ~1,000 trace entries. The gas cost per iteration includes at least one storage read (`pool_member_trace.at(entry_to_claim_from)`) and one `find_sigma` call (another storage read). At Starknet's current gas model, a few thousand such iterations can exhaust a transaction's gas budget.

The developers themselves acknowledge the risk in a code comment: *"This loop is unbounded but unlikely to exceed gas limits."* — this is an optimistic assumption, not a guarantee. [6](#0-5) 

### Recommendation

1. **Introduce a partial-claim mechanism**: Allow `claim_rewards` to accept a `max_entries` parameter, process at most that many trace entries per call, and advance `entry_to_claim_from` accordingly. This lets a delegator with a large trace drain it over multiple transactions.

2. **Bound balance-change frequency**: Enforce that a pool member can only create one new trace entry per epoch (the `insert` function already deduplicates same-epoch calls, but this should be documented as a deliberate gas-safety invariant).

3. **Emit a warning or revert early**: If `pool_member_trace_length - entry_to_claim_from` exceeds a configurable threshold, revert with a descriptive error rather than silently running out of gas.

### Proof of Concept

```
1. Delegator D enters pool with minimum stake.
2. For epoch i = 1 to N (e.g., N = 2000):
     a. Advance to epoch i.
     b. Call add_to_delegation_pool(pool_member: D, amount: 1).
        → set_member_balance inserts a new checkpoint at epoch i + K.
3. After N epochs, pool_member_epoch_balance[D] has N checkpoints.
4. Call claim_rewards(pool_member: D).
   → calculate_rewards loops N times, each iteration reading storage.
   → Transaction runs out of gas and reverts.
5. D's accumulated yield is permanently frozen; no future claim can succeed
   because entry_to_claim_from was never advanced.
```

The trace insertion path is:
`add_to_delegation_pool` → `increase_member_balance` → `set_member_balance` → `trace.insert` [7](#0-6) [1](#0-0)

### Citations

**File:** src/pool/pool.cairo (L233-233)
```text
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
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

**File:** src/pool/pool.cairo (L734-739)
```text
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
