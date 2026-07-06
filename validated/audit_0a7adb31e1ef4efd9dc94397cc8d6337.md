### Title
Unbounded Loop Over Pool Member Balance Trace in `calculate_rewards` Enables Permanent Freezing of Unclaimed Yield - (File: src/pool/pool.cairo)

### Summary

The `calculate_rewards` function in `src/pool/pool.cairo` contains an explicitly acknowledged unbounded `while` loop that iterates over a pool member's entire balance-change trace. Because the trace grows by one entry per epoch in which the member changes their balance, a delegator who makes balance changes across many epochs without claiming rewards will eventually accumulate a trace large enough to cause `claim_rewards` to exceed Starknet's per-transaction gas limit, permanently bricking their ability to collect accrued yield.

### Finding Description

**Root cause — unbounded loop over attacker-grown storage:**

`calculate_rewards` (line 837) iterates from `entry_to_claim_from` to `pool_member_trace_length` with no upper-bound cap:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
``` [1](#0-0) 

The trace (`pool_member_epoch_balance`) is a `PoolMemberBalanceTrace` backed by a `Vec` of checkpoints. The `insert` implementation appends a **new** checkpoint whenever the insertion epoch differs from the last stored epoch:

```cairo
} else {
    assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
``` [2](#0-1) 

Every public function that mutates a member's balance calls `set_member_balance` (or `increase_member_balance`), which calls `trace.insert(key: self.get_epoch_plus_k(), ...)`:

- `enter_delegation_pool` → `set_member_balance` (line 201)
- `add_to_delegation_pool` → `increase_member_balance` (line 242)
- `exit_delegation_pool_intent` → `set_member_balance` (line 278) [3](#0-2) 

Because `insert` deduplicates within the same epoch, the trace grows at most **one entry per epoch** in which a balance change occurs. The `entry_to_claim_from` cursor stored in `pool_member_info` advances only when `claim_rewards` is successfully called:

```cairo
pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
``` [4](#0-3) 

If a delegator makes balance changes every epoch but defers claiming rewards, the gap `pool_member_trace_length - entry_to_claim_from` grows without bound. When `claim_rewards` is eventually called, the loop must traverse every accumulated entry. Once the trace is large enough, the transaction exceeds the Starknet gas limit and reverts. Because the cursor is only advanced inside the same atomic transaction, no partial progress is saved — every subsequent `claim_rewards` attempt also reverts, permanently locking the yield.

**Entry path (unprivileged delegator):**

1. Delegator calls `enter_delegation_pool` — trace entry 1 created.
2. Each epoch: delegator calls `add_to_delegation_pool` (minimum amount) or `exit_delegation_pool_intent` / re-enters — one new trace entry per epoch.
3. Delegator never calls `claim_rewards` (or calls it infrequently).
4. After *N* epochs of balance changes, `pool_member_trace_length` = *N*.
5. `claim_rewards` → `calculate_rewards` must loop *N* times; at sufficient *N* the transaction OOGs and reverts.
6. All future `claim_rewards` calls also revert — yield is permanently frozen.

`claim_rewards` is restricted to the pool member or their reward address, so no external party can force a claim or rescue the funds:

```cairo
assert!(
    caller_address == pool_member || caller_address == reward_address,
    "{}",
    Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
);
``` [5](#0-4) 

### Impact Explanation

**Severity: High — Permanent freezing of unclaimed yield.**

Once the trace is large enough to exceed the gas limit, the delegator's entire accumulated unclaimed yield becomes permanently inaccessible. There is no escape hatch: `claim_rewards` is the only withdrawal path for yield, and no partial-progress mechanism exists. The delegator's staked principal is unaffected (it can still be withdrawn via `exit_delegation_pool_intent` / `exit_delegation_pool_action`), but all accrued rewards are frozen forever.

### Likelihood Explanation

**Medium.** The trace grows at most one entry per epoch. If epochs are on the order of days, accumulating thousands of entries takes years of continuous active participation without claiming. However:

- The protocol explicitly acknowledges the loop is unbounded ("This loop is unbounded but unlikely to exceed gas limits") — the developers themselves flag this as a known risk.
- A delegator who actively manages their position (e.g., topping up or partially exiting every epoch) over a multi-year horizon will naturally accumulate a large trace.
- There is no protocol-enforced maximum trace length or mandatory periodic claim.
- A malicious actor who wants to permanently freeze their own yield (e.g., to grief a staker's reputation or test limits) can do so deliberately at low cost.

### Recommendation

1. **Cap the loop per call.** Introduce a `max_entries_per_claim` constant and process at most that many trace entries per `claim_rewards` invocation, saving the updated `entry_to_claim_from` cursor so subsequent calls continue from where the last left off. This already works structurally since `entry_to_claim_from` is persisted.
2. **Enforce a maximum trace length.** In `set_member_balance`, assert that the trace length does not exceed a safe constant (e.g., 1 000 entries). Reject balance changes that would exceed this limit, or require the member to claim rewards first.
3. **Periodic forced checkpointing.** Require `claim_rewards` to be called before any balance change that would add a new trace entry beyond a threshold.

### Proof of Concept

```
Epoch 1:  delegator calls enter_delegation_pool(amount=1)       → trace length = 1
Epoch 2:  delegator calls add_to_delegation_pool(amount=1)      → trace length = 2
Epoch 3:  delegator calls exit_delegation_pool_intent(amount=1) → trace length = 3
...
Epoch N:  (balance change every epoch, no claim_rewards called) → trace length = N

Epoch N+1: delegator calls claim_rewards
           → calculate_rewards loops N times
           → at N ≈ gas_limit / cost_per_iteration, transaction OOGs
           → entry_to_claim_from NOT updated (revert)
           → all future claim_rewards calls also OOG
           → unclaimed yield permanently frozen
```

The exact threshold *N* depends on Starknet's current gas pricing for storage reads inside the loop (each iteration calls `pool_member_trace.at(entry_to_claim_from)` — a storage read — plus `find_sigma` which performs additional storage reads on `cumulative_rewards_trace`). [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** src/pool/pool.cairo (L201-201)
```text
            self.set_member_balance(:pool_member, :amount);
```

**File:** src/pool/pool.cairo (L242-242)
```text
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
```

**File:** src/pool/pool.cairo (L278-278)
```text
            self.set_member_balance(:pool_member, amount: new_delegated_stake);
```

**File:** src/pool/pool.cairo (L340-344)
```text
            assert!(
                caller_address == pool_member || caller_address == reward_address,
                "{}",
                Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );
```

**File:** src/pool/pool.cairo (L358-359)
```text
            pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
            pool_member_info.reward_checkpoint = until_checkpoint;
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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L169-173)
```text
        } else {
            // Checkpoint keys must be non-decreasing.
            assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
            checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
        }
```
