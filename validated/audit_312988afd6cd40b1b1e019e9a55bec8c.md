### Title
Unbounded `pool_member_epoch_balance` Trace Causes Gas Exhaustion in `calculate_rewards` - (`src/pool/pool.cairo`)

---

### Summary

A pool member (delegator) can grow their `pool_member_epoch_balance` trace without bound by repeatedly entering and exiting the delegation pool across different epochs. The `calculate_rewards` internal function iterates over every entry in this trace without any cap. When the trace is large enough, any state-changing call that invokes `calculate_rewards` — including `claim_rewards` and `exit_delegation_pool_action` — will permanently revert due to gas exhaustion, permanently freezing the delegator's staked funds.

---

### Finding Description

In `src/pool/pool.cairo`, the `calculate_rewards` function iterates over the entire `pool_member_epoch_balance` trace for a given pool member: [1](#0-0) 

The code itself acknowledges the risk with the comment: *"This loop is unbounded but unlikely to exceed gas limits."* However, the trace grows by one entry every time a delegator changes their balance in a new epoch. There is no cap on the number of entries, and no mechanism to prune old entries.

The trace is appended to each time a delegator calls `enter_delegation_pool`, `exit_delegation_pool_intent` (partial), or `switch_staking_delegation_pool` — any operation that records a new balance checkpoint in a new epoch. A delegator who performs N such operations across N distinct epochs will accumulate N entries in their trace.

`calculate_rewards` is invoked inside state-changing functions:
- `claim_rewards` (delegator claims accumulated rewards)
- `exit_delegation_pool_action` (delegator withdraws their stake)

Both of these are the only paths through which a delegator can recover their staked tokens.

---

### Impact Explanation

Once the `pool_member_epoch_balance` trace for a delegator grows large enough to cause `calculate_rewards` to exhaust the Starknet transaction gas limit, every call to `claim_rewards` and `exit_delegation_pool_action` for that delegator will revert. The delegator's staked funds become permanently inaccessible — a permanent freeze of funds.

This matches the allowed impact: **Permanent freezing of unclaimed yield or unclaimed royalties; Temporary freezing of funds** (and in the worst case, permanent freezing of principal).

---

### Likelihood Explanation

The attack is self-inflicted or can be induced by a griefing attacker who controls a delegator address. The cost is proportional to the number of epochs traversed (one transaction per epoch per new checkpoint). On Starknet with short epoch durations, accumulating hundreds of checkpoints is realistic over months of normal usage. A malicious delegator can also deliberately cycle enter/exit across epochs to inflate their own trace and then claim the funds are frozen — or a protocol integrator could inadvertently trigger this through automated rebalancing.

---

### Recommendation

1. **Checkpoint pruning on claim**: When `calculate_rewards` processes entries up to `entry_to_claim_from`, persist the updated `entry_to_claim_from` index in the pool member's checkpoint so future calls start from where the last claim left off, rather than re-scanning from the beginning. (The function already returns `entry_to_claim_from` — it should be stored.)
2. **Bound the trace length**: Enforce a maximum number of balance-change entries per pool member per epoch, or merge consecutive entries in the same epoch.
3. **Paginated reward claiming**: Allow partial reward claims over a bounded number of trace entries per transaction.

---

### Proof of Concept

1. Delegator calls `enter_delegation_pool` in epoch E₀ → trace length = 1.
2. Delegator calls `exit_delegation_pool_intent` (partial) in epoch E₁ → trace length = 2.
3. Delegator calls `enter_delegation_pool` again in epoch E₂ → trace length = 3.
4. Repeat steps 2–3 across N epochs → trace length = N.
5. When N is large enough (e.g., several thousand entries), delegator calls `claim_rewards` or `exit_delegation_pool_action`.
6. `calculate_rewards` enters the `while entry_to_claim_from < pool_member_trace_length` loop at [2](#0-1)  and iterates N times, exhausting the transaction gas limit.
7. The transaction reverts. All subsequent attempts to claim rewards or withdraw stake also revert. The delegator's funds are permanently frozen.

### Citations

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
