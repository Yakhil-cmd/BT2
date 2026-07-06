### Title
Unbounded Loop in `calculate_rewards` Enables Permanent Freezing of Unclaimed Yield via Trace Accumulation - (File: src/pool/pool.cairo)

### Summary
A pool member (delegator) can accumulate an arbitrarily large `pool_member_epoch_balance` trace by making balance-changing calls (`add_to_delegation_pool`, `exit_delegation_pool_intent`) across many epochs without claiming rewards. When `claim_rewards` is eventually called, it iterates over every accumulated trace entry in an unbounded loop. If the trace is large enough, the transaction runs out of gas, permanently freezing the delegator's unclaimed yield with no alternative recovery path. The code itself acknowledges this risk with an inline comment.

### Finding Description

**Root cause:** `calculate_rewards` in `src/pool/pool.cairo` (lines 837–888) contains an explicitly unbounded loop over the `pool_member_epoch_balance` trace:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
``` [1](#0-0) 

The trace grows by one entry per epoch in which the delegator modifies their balance. Three public entry points each call `set_member_balance`, which calls `trace.insert(key: self.get_epoch_plus_k(), ...)`:

- `enter_delegation_pool` → `set_member_balance` [2](#0-1) 
- `add_to_delegation_pool` → `increase_member_balance` → `set_member_balance` [3](#0-2) 
- `exit_delegation_pool_intent` → `set_member_balance` [4](#0-3) 

`set_member_balance` inserts with key `current_epoch + K`, so each call in a distinct epoch appends a new entry: [5](#0-4) 

`claim_rewards` calls `calculate_rewards` starting from `pool_member_info.entry_to_claim_from`, which is only advanced on a *successful* claim: [6](#0-5) 

If the trace has grown to N entries since the last successful claim, the loop must execute N iterations. There is no partial-claim mechanism and no cap on trace length.

**Attack path:**
1. Delegator calls `enter_delegation_pool` (epoch 0).
2. Each subsequent epoch, delegator calls `add_to_delegation_pool` with the minimum amount, or alternates `add_to_delegation_pool` / `exit_delegation_pool_intent` — each call in a new epoch appends one entry to the trace.
3. Delegator never calls `claim_rewards`, so `entry_to_claim_from` stays at 0.
4. After N epochs of balance changes, the trace has N entries.
5. Any call to `claim_rewards` (by the pool member or their reward address) must iterate all N entries. At a sufficiently large N, the transaction exceeds the Starknet gas limit and reverts.
6. Because `entry_to_claim_from` is only updated on success, and there is no partial-claim path, the rewards are permanently unclaimable.

The same unbounded loop is also triggered by the view function `pool_member_info_v1`: [7](#0-6) 

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

Once the trace is large enough that `claim_rewards` consistently runs out of gas, the delegator's accumulated rewards are permanently locked in the contract. There is no administrative recovery function, no partial-claim path, and no way to truncate the trace. The STRK rewards are irrecoverably frozen for the affected pool member.

### Likelihood Explanation
**Low-to-Medium.** A delegator who actively manages their position (partial exits, re-delegations) across many epochs without claiming rewards can reach this state organically. A malicious actor can reach it deliberately at the cost of one transaction per epoch. Starknet's per-transaction gas limit is finite and well-defined; the number of epochs required to trigger the condition is bounded and calculable. The protocol's own comment ("This loop is unbounded but unlikely to exceed gas limits") confirms the developers are aware of the risk but have not mitigated it.

### Recommendation
1. **Partial claiming:** Allow `claim_rewards` to accept a `max_entries` parameter, processing at most that many trace entries per call and saving progress so subsequent calls continue from where the last left off.
2. **Claim-on-change:** Automatically settle accrued rewards into `_unclaimed_rewards_from_v0` whenever `set_member_balance` is called, then reset `entry_to_claim_from` to the current trace length. This bounds the loop to at most a small constant number of entries per claim.
3. **Trace compaction:** After a successful claim, truncate processed entries from the trace so its length is bounded by the number of balance changes since the last claim.

### Proof of Concept

```
Epoch 0:  delegator calls enter_delegation_pool(amount=MIN)
           → trace length = 1, entry_to_claim_from = 0

Epoch 1:  delegator calls add_to_delegation_pool(amount=1)
           → trace length = 2

Epoch 2:  delegator calls exit_delegation_pool_intent(amount=1)
           → trace length = 3

... repeat for N epochs without ever calling claim_rewards ...

Epoch N:  delegator (or reward_address) calls claim_rewards(pool_member)
           → calculate_rewards loops from entry 0 to entry N
           → if N > gas_limit / cost_per_iteration, transaction reverts
           → entry_to_claim_from remains 0
           → all subsequent claim_rewards calls also revert
           → unclaimed yield is permanently frozen
```

The cost per loop iteration includes two `find_sigma` calls (each reading from `cumulative_rewards_trace`) and arithmetic, making the per-iteration gas cost non-trivial. The exact threshold N can be determined empirically on a fork test.

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

**File:** src/pool/pool.cairo (L349-358)
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
```

**File:** src/pool/pool.cairo (L532-538)
```text
            let (rewards, _) = self
                .calculate_rewards(
                    :pool_member,
                    from_checkpoint: pool_member_info.reward_checkpoint,
                    until_checkpoint: self.get_current_checkpoint(:pool_member),
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
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
