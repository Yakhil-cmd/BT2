### Title
Unbounded Loop in `calculate_rewards` Allows Permanent Freezing of Delegator Unclaimed Yield via Trace Inflation - (File: src/pool/pool.cairo)

---

### Summary

The `calculate_rewards` function in `pool.cairo` contains an explicitly acknowledged unbounded loop that iterates over every entry in a pool member's `pool_member_epoch_balance` trace. Because each call to `add_to_delegation_pool` or `exit_delegation_pool_intent` in a distinct epoch appends a new checkpoint to this trace, a delegator who makes frequent balance changes without claiming rewards will grow the trace without bound. Once the trace is large enough, every call to `claim_rewards` (and `pool_member_info_v1`) will exceed Starknet's per-transaction gas limit, permanently freezing the delegator's accumulated yield.

---

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` iterates over the entire unclaimed portion of a pool member's balance trace:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch { break; }
    ...
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

The trace grows via `set_member_balance`, which calls `trace.insert(key: self.get_epoch_plus_k(), ...)`. The `insert` function only deduplicates when the incoming key equals the last stored key; otherwise it pushes a new checkpoint:

```cairo
if last.key == key {
    last.value = value;
    checkpoints[len - 1].write(last);
} else {
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
``` [2](#0-1) 

Because `get_epoch_plus_k()` returns `current_epoch + K`, every balance-changing call made in a **different epoch** appends a distinct entry. Both `add_to_delegation_pool` and `exit_delegation_pool_intent` trigger this path: [3](#0-2) [4](#0-3) 

The `entry_to_claim_from` cursor is only advanced inside `claim_rewards`: [5](#0-4) 

If a delegator never calls `claim_rewards`, the cursor stays at 0 and the loop must traverse every accumulated entry on the next claim attempt. There is no cap on how many entries can accumulate.

`pool_member_info_v1` (the read-only view) also calls `calculate_rewards` unconditionally, so even querying the member's state becomes impossible once the trace is large enough: [6](#0-5) 

---

### Impact Explanation

Once the trace length exceeds the gas budget for a single Starknet transaction, every invocation of `claim_rewards` and `pool_member_info_v1` for that pool member will revert. The delegator's accumulated STRK rewards become permanently unclaimable. This matches the allowed impact: **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

- Any delegator who calls `add_to_delegation_pool` or `exit_delegation_pool_intent` once per epoch without claiming rewards grows the trace by one entry per epoch.
- There is no protocol-enforced maximum on how long a delegator can go without claiming.
- Starknet's per-transaction gas limit is finite and well-defined; a sufficiently large trace will deterministically exceed it.
- The developers themselves acknowledge the risk in a code comment: *"This loop is unbounded but unlikely to exceed gas limits"* — this is an optimistic assumption, not a guarantee.
- A delegator who has been active for hundreds of epochs and adjusts their stake regularly (a normal usage pattern) can reach this state organically, without any adversarial intent.

---

### Recommendation

1. **Enforce a claim before balance changes**: Require `claim_rewards` to be called (or auto-call it internally) before any balance-modifying operation, so `entry_to_claim_from` is always advanced to the current trace length before a new entry is appended. This bounds the loop to at most a small constant number of entries per call.
2. **Alternatively, cap the loop**: Introduce a maximum iteration count per `claim_rewards` call and allow partial claims, storing the updated `entry_to_claim_from` so subsequent calls continue from where the previous one stopped.
3. **Remove the optimistic comment** and treat this as a hard invariant to enforce.

---

### Proof of Concept

```
Epoch 1:  delegator calls enter_delegation_pool(amount=X)
          → trace: [(epoch=1+K, balance=X)]

Epoch 2:  delegator calls add_to_delegation_pool(amount=1)
          → trace: [(epoch=1+K, X), (epoch=2+K, X+1)]

Epoch 3:  delegator calls add_to_delegation_pool(amount=1)
          → trace: [(epoch=1+K, X), (epoch=2+K, X+1), (epoch=3+K, X+2)]

...

Epoch N:  delegator calls add_to_delegation_pool(amount=1)
          → trace length = N

Epoch N+1: delegator calls claim_rewards()
           → calculate_rewards loops N times
           → if N > gas_limit / cost_per_iteration → REVERT (out of gas)
           → delegator's rewards are permanently frozen
```

The attacker-controlled entry path is entirely unprivileged: `add_to_delegation_pool` is callable by any existing pool member or their reward address with no special role required. [7](#0-6)

### Citations

**File:** src/pool/pool.cairo (L221-233)
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
```

**File:** src/pool/pool.cairo (L241-243)
```text
            // Update the pool member's balance checkpoint.
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
            let new_delegated_stake = old_delegated_stake + amount;
```

**File:** src/pool/pool.cairo (L277-278)
```text
            // Update the pool member's balance checkpoint.
            self.set_member_balance(:pool_member, amount: new_delegated_stake);
```

**File:** src/pool/pool.cairo (L348-359)
```text
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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L163-173)
```text
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
```
