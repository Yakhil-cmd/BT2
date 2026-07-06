### Title
Unbounded Loop in `calculate_rewards` Enables Permanent Freezing of Delegator's Unclaimed Yield - (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` internal function in the pool contract iterates over a delegator's `pool_member_epoch_balance` trace without any bound. Every call to `add_to_delegation_pool` or `exit_delegation_pool_intent` in a new epoch appends a new checkpoint to this trace. A delegator who repeatedly calls `add_to_delegation_pool` with the minimum non-zero amount across many epochs can grow their trace arbitrarily large. Once the trace is large enough, any subsequent `claim_rewards` call for that delegator will exceed the Starknet block gas limit, permanently freezing their unclaimed yield.

---

### Finding Description

**Root cause — the unbounded loop:**

`calculate_rewards` in `src/pool/pool.cairo` (lines 837–888) iterates over every entry in `pool_member_epoch_balance` for the given pool member. The developers themselves acknowledge this in a comment:

```
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
```

Each iteration reads a checkpoint from storage and calls `find_sigma`, which itself performs additional storage reads into `cumulative_rewards_trace`. The per-iteration cost is therefore non-trivial.

**How the trace grows:**

`set_member_balance` (line 718) calls `trace.insert(key: self.get_epoch_plus_k(), value: ...)`. The `insert` implementation in `src/pool/pool_member_balance_trace/trace.cairo` (lines 152–175) appends a **new** checkpoint whenever the key (current epoch + K) differs from the last stored key — i.e., whenever the call happens in a different epoch than the previous balance change.

`add_to_delegation_pool` (line 221) calls `increase_member_balance` → `set_member_balance`, and its only amount guard is:

```cairo
assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
```

So 1 wei is sufficient per call.

`exit_delegation_pool_intent` (line 256) also calls `set_member_balance` unconditionally (line 278), regardless of the `amount` argument.

**Attack path:**

1. Attacker enters the delegation pool via `enter_delegation_pool`.
2. Each epoch, attacker calls `add_to_delegation_pool(pool_member: self, amount: 1)`. Because the epoch has advanced, `get_epoch_plus_k()` returns a new key, and a new checkpoint is appended.
3. After N epochs, `pool_member_epoch_balance` for the attacker contains N entries.
4. Attacker (or anyone) calls `claim_rewards` for the attacker's address. `calculate_rewards` loops N times, each time reading from two separate storage traces. The transaction runs out of gas and reverts.
5. The attacker's accumulated unclaimed yield is permanently inaccessible.

The 1-wei tokens deposited each epoch are locked in the staking contract but the total ETH cost is negligible compared to the damage.

**Where `calculate_rewards` is invoked:**

`claim_rewards` in the pool contract calls `calculate_rewards` for the pool member. Once the trace is large enough, every `claim_rewards` call for that member will revert, with no recovery path.

---

### Impact Explanation

**Severity: High — Permanent freezing of unclaimed yield.**

Once the `pool_member_epoch_balance` trace for a delegator grows beyond the threshold that causes `calculate_rewards` to exhaust the block gas limit, that delegator's unclaimed rewards are permanently inaccessible. There is no administrative escape hatch, no pagination mechanism, and no way to compact or prune the trace after the fact. All rewards accrued up to that point are frozen forever.

---

### Likelihood Explanation

**Medium likelihood.**

- The attack requires the attacker to call `add_to_delegation_pool` once per epoch for many epochs. On Starknet, epochs are measured in blocks; the exact number of epochs needed depends on the per-iteration gas cost of `calculate_rewards` relative to the block gas limit.
- The cost per epoch is minimal: one transaction + 1 wei of token (recoverable in principle, though the attacker would also be unable to exit cleanly once the trace is large).
- The attack can also occur **accidentally** for legitimate long-term delegators who frequently adjust their delegation across many epochs — a realistic scenario for active participants.
- No privileged access is required; any pool member can trigger this against themselves.

---

### Recommendation

Add a maximum bound on the number of loop iterations in `calculate_rewards`, and implement a checkpoint-based pagination mechanism so that reward claims can be split across multiple transactions. Specifically:

1. Introduce a `max_iterations` constant and break the loop after that many steps, storing the `entry_to_claim_from` cursor in the pool member's state so the next `claim_rewards` call resumes from where the previous one stopped.
2. Alternatively, enforce a maximum number of balance-change checkpoints per pool member (e.g., by compacting consecutive same-epoch entries or capping the trace length).

---

### Proof of Concept

**Setup:**
- Staker is active with a delegation pool open.
- Attacker enters the pool with a small amount.

**Steps:**
```
for epoch in 1..N:
    advance_epoch()
    pool.add_to_delegation_pool(pool_member: attacker, amount: 1)
    // Each call appends one new entry to pool_member_epoch_balance[attacker]
    // because get_epoch_plus_k() returns a strictly increasing key each epoch.

// After N iterations, pool_member_epoch_balance[attacker].length() == N

pool.claim_rewards(pool_member: attacker)
// calculate_rewards loops N times, each iteration reads from two storage traces.
// Transaction runs out of gas and reverts.
// Attacker's unclaimed rewards are permanently frozen.
```

**Key code references:**

- Unbounded loop: [1](#0-0) 
- Trace insertion (one entry per new epoch): [2](#0-1) 
- `add_to_delegation_pool` minimum-amount guard (only `> 0`): [3](#0-2) 
- `set_member_balance` inserts with key `epoch + K`: [4](#0-3) 
- `exit_delegation_pool_intent` also calls `set_member_balance` unconditionally: [5](#0-4)

### Citations

**File:** src/pool/pool.cairo (L233-233)
```text
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
```

**File:** src/pool/pool.cairo (L277-279)
```text
            // Update the pool member's balance checkpoint.
            self.set_member_balance(:pool_member, amount: new_delegated_stake);

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
