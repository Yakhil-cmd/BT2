### Title
Unbounded Loop in `calculate_rewards` Allows Permanent Freezing of Pool Member Unclaimed Yield - (File: src/pool/pool.cairo)

### Summary

The `calculate_rewards` internal function in `src/pool/pool.cairo` contains an unbounded loop that iterates over every entry in a pool member's `pool_member_epoch_balance` trace since their last claim. A pool member who makes one balance change per epoch without ever claiming rewards will grow this trace without limit. Once the trace is large enough, both `claim_rewards` and the view function `pool_member_info_v1` will consume gas proportional to the trace length, eventually causing transactions to revert and permanently freezing the pool member's unclaimed yield.

The code itself acknowledges the risk with the comment: *"This loop is unbounded but unlikely to exceed gas limits."*

---

### Finding Description

`calculate_rewards` iterates from `entry_to_claim_from` to `pool_member_trace_length`, calling `find_sigma` (a storage read) on every iteration: [1](#0-0) 

The trace (`pool_member_epoch_balance`) grows by one entry per epoch whenever a pool member calls `add_to_delegation_pool` or `exit_delegation_pool_intent` in a new epoch. The `insert` function only deduplicates within the same epoch key; different epoch keys always append a new checkpoint: [2](#0-1) 

The key used for insertion is `current_epoch + K`: [3](#0-2) 

The loop counter `entry_to_claim_from` is only advanced when `claim_rewards` is called and its updated value is written back to storage: [4](#0-3) 

If a pool member never calls `claim_rewards`, `entry_to_claim_from` stays at 0 and the loop must traverse the entire trace on every invocation.

Both `claim_rewards` and the view function `pool_member_info_v1` call `calculate_rewards`: [5](#0-4) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Once the trace is large enough that a single `claim_rewards` call exceeds the Starknet transaction gas limit, the pool member can never successfully claim their accumulated rewards. The rewards remain locked in the pool contract with no recovery path, because:

- There is no partial-claim mechanism (no `from`/`to` epoch range parameter).
- `entry_to_claim_from` can only be advanced by a successful `claim_rewards` execution.
- The pool member cannot reduce the trace length retroactively.

Additionally, `pool_member_info_v1` (a view function also calling `calculate_rewards`) becomes permanently unusable for that pool member, breaking off-chain tooling and any on-chain integrations that read pool member state.

---

### Likelihood Explanation

**Medium.**

The trace grows at most one entry per epoch. A pool member must make at least one balance change per epoch and defer claiming for a sustained period. While this requires deliberate or negligent behavior over many epochs, the minimum delegation amount is not zero (any non-zero amount suffices per `add_to_delegation_pool`), and there is no protocol-enforced upper bound on the trace length. A pool member who routinely adjusts their delegation without claiming — a plausible pattern for active participants — will organically approach the gas limit over time. The code authors themselves flagged this as a known risk.

---

### Recommendation

1. **Add a `max_entries` parameter** to `calculate_rewards` so callers can process the trace in bounded batches, advancing `entry_to_claim_from` incrementally across multiple transactions.
2. **Alternatively**, enforce a maximum trace length by requiring pool members to claim rewards before making a new balance change when the trace exceeds a threshold.
3. **At minimum**, remove the comment dismissing the risk and document the maximum safe trace length given Starknet's current gas limits.

---

### Proof of Concept

1. Pool member `A` enters a delegation pool with the minimum allowed amount.
2. Every epoch, `A` calls `add_to_delegation_pool` with 1 unit, adding one new entry to `pool_member_epoch_balance` (key = `current_epoch + K`).
3. `A` never calls `claim_rewards`, so `entry_to_claim_from` remains `0`.
4. After `N` epochs, the trace has `N` entries.
5. `A` (or anyone) calls `claim_rewards` or `pool_member_info_v1` for `A`.
6. `calculate_rewards` enters the loop at line 859 and iterates `N` times, each iteration performing a storage read via `find_sigma`.
7. For sufficiently large `N`, the transaction reverts due to gas exhaustion.
8. `A`'s accumulated rewards are permanently frozen — `entry_to_claim_from` can never advance past 0. [6](#0-5)

### Citations

**File:** src/pool/pool.cairo (L349-359)
```text
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
