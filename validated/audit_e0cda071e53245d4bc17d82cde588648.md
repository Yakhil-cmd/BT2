### Title
Unbounded `pool_member_epoch_balance` Trace Growth Causes Permanent Freezing of Unclaimed Yield — (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` function in `Pool` iterates over every entry in a pool member's `pool_member_epoch_balance` trace in an unbounded loop. Each epoch in which a pool member changes their balance appends a new checkpoint to this trace. A pool member who regularly adjusts their delegation across many epochs without claiming rewards will accumulate an arbitrarily large trace. Eventually, the `claim_rewards` (and `pool_member_info_v1`) call will exhaust the Starknet transaction step budget, permanently freezing the pool member's unclaimed yield with no recovery path.

---

### Finding Description

**Root cause — the unbounded loop:**

In `src/pool/pool.cairo`, `calculate_rewards` (lines 857–877) iterates over every entry in `pool_member_epoch_balance` from `entry_to_claim_from` to `pool_member_trace_length`. The developers themselves annotate this:

```
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
```

**How the trace grows:**

`set_member_balance` (lines 718–729) inserts a checkpoint keyed at `current_epoch + K`:

```cairo
trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance);
```

The underlying `insert` implementation (in `src/pool/pool_member_balance_trace/trace.cairo`, lines 152–175) only updates the last entry if the key matches; otherwise it **appends** a new entry. Since the key is `current_epoch + K`, every epoch in which a balance change occurs produces a distinct key and therefore a new checkpoint. The trace grows by exactly one entry per epoch of balance activity.

**Functions that append to the trace:**

- `enter_delegation_pool` → calls `set_member_balance` (line 201)
- `add_to_delegation_pool` → calls `increase_member_balance` → `set_member_balance` (line 242)
- `exit_delegation_pool_intent` → calls `set_member_balance` (line 278)
- `enter_delegation_pool_from_staking_contract` → calls `increase_member_balance` or `set_member_balance` (lines 456, 464)

**`entry_to_claim_from` does not prevent unbounded growth:**

`entry_to_claim_from` is stored in `pool_member_info` and advanced after each successful `claim_rewards` call (line 358). This means the loop only processes entries since the last claim. However, if a pool member changes their balance every epoch for N epochs without claiming, the loop must process all N entries in a single transaction. There is no batching mechanism and no cap on N.

**Where `calculate_rewards` is called:**

- `claim_rewards` (line 349–355): state-changing, restricted to pool member or reward address.
- `pool_member_info_v1` (lines 532–538): view function, callable by anyone, also iterates the full trace.

---

### Impact Explanation

A pool member who changes their delegation balance once per epoch (via `add_to_delegation_pool` or `exit_delegation_pool_intent`) and defers claiming rewards will accumulate one trace entry per epoch. After enough epochs, the `claim_rewards` transaction will exceed the Starknet step limit and revert. Because `entry_to_claim_from` is only advanced on a successful claim, and there is no partial-claim or skip mechanism, the pool member's unclaimed yield becomes permanently frozen — they can never successfully execute `claim_rewards` again.

This matches the allowed impact: **High — Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

The attack is self-inflicted: only the pool member or their reward address can call the balance-changing functions. However, this is a realistic scenario for any long-lived delegator who:

1. Regularly adjusts their delegation (e.g., dollar-cost averaging in or out), and
2. Does not claim rewards every epoch (a common pattern for passive participants).

The protocol imposes no upper bound on the trace length and no minimum claim frequency. The developers acknowledge the loop is unbounded. On Starknet, the per-transaction step budget is finite (typically ~10 million steps); each loop iteration involves multiple storage reads and arithmetic operations, making exhaustion reachable within hundreds to low thousands of epochs of unclaimed balance changes.

---

### Recommendation

1. **Introduce a `max_entries_per_claim` parameter** and process only a bounded slice of the trace per `claim_rewards` call, storing the updated `entry_to_claim_from` so subsequent calls continue from where the last left off.
2. Alternatively, **enforce a maximum trace length** by requiring pool members to claim rewards before their trace exceeds a threshold.
3. At minimum, **document the risk** and add an on-chain guard that reverts with a clear error if `pool_member_trace_length - entry_to_claim_from` exceeds a safe constant.

---

### Proof of Concept

1. Pool member Alice enters a delegation pool at epoch E₀.
2. Each epoch, Alice calls `add_to_delegation_pool` with a small amount, then `exit_delegation_pool_intent` to partially reduce her balance. Each pair of calls in different epochs appends two entries to her `pool_member_epoch_balance` trace.
3. Alice never calls `claim_rewards`.
4. After N epochs, Alice's trace has ~2N entries. `entry_to_claim_from` is still 0.
5. Alice calls `claim_rewards`. The loop in `calculate_rewards` must iterate ~2N times, each iteration reading from storage (`pool_member_trace.at(entry_to_claim_from)`) and calling `find_sigma`.
6. For sufficiently large N, the transaction exceeds the Starknet step budget and reverts.
7. Because `entry_to_claim_from` was never updated (the transaction reverted), every future `claim_rewards` attempt also reverts. Alice's accumulated yield is permanently frozen.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** src/pool/pool.cairo (L335-358)
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
