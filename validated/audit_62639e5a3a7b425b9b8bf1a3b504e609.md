### Title
Unbounded loop in `calculate_rewards` can permanently freeze pool member's unclaimed yield — (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` internal function in `pool.cairo` contains an explicitly self-acknowledged unbounded loop that iterates over every balance-change entry in a pool member's `pool_member_epoch_balance` trace. A pool member who accumulates many balance-change entries across epochs without claiming rewards can cause `claim_rewards` (and the view `pool_member_info_v1`) to revert out-of-gas, permanently freezing their unclaimed yield.

---

### Finding Description

`calculate_rewards` iterates over the entire `pool_member_epoch_balance` trace from `entry_to_claim_from` up to the current epoch: [1](#0-0) 

The developers themselves annotated this loop:

> **Note**: The loop iterates over the balance changes in the pool member's balance trace. **This loop is unbounded but unlikely to exceed gas limits.**

The trace (`pool_member_epoch_balance`) is a `PoolMemberBalanceTrace` stored per pool member: [2](#0-1) 

Every call that changes a pool member's delegated balance appends a new checkpoint to this trace:
- `add_to_delegation_pool` → `increase_member_balance` [3](#0-2) 
- `exit_delegation_pool_intent` → `set_member_balance` [4](#0-3) 
- `enter_delegation_pool_from_staking_contract` → `increase_member_balance` / `set_member_balance` [5](#0-4) 

`calculate_rewards` is called from two public entry points:

1. **`claim_rewards`** — callable by the pool member or their reward address: [6](#0-5) 

2. **`pool_member_info_v1`** — a public view callable by anyone: [7](#0-6) 

`entry_to_claim_from` is advanced after each successful `claim_rewards` call: [8](#0-7) 

However, `pool_member_info_v1` never advances `entry_to_claim_from`, so repeated view calls do not reduce the loop size. More critically, if a pool member makes balance changes across many epochs without claiming, the gap between `entry_to_claim_from` and the current trace length grows proportionally to the number of epochs elapsed, making the loop arbitrarily large.

There is **no cap** on the number of entries in `pool_member_epoch_balance` and no pagination mechanism in `calculate_rewards`.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Once the trace is large enough that `calculate_rewards` exhausts the Starknet transaction gas limit, `claim_rewards` will always revert. The pool member's accumulated STRK rewards become permanently unclaimable. The reward address (which may be a different account from the pool member) is equally affected.

---

### Likelihood Explanation

**Medium.** The trace grows at most once per epoch per pool member (epoch-keyed checkpoints). However:
- Starknet epochs are short (a few hours), so a long-term delegator who makes balance changes regularly (e.g., topping up stake each epoch) and defers claiming rewards will accumulate hundreds or thousands of trace entries over months.
- No privileged access is required — any pool member can reach this state through normal protocol usage.
- The developers themselves flagged the loop as unbounded, acknowledging the risk.

---

### Recommendation

1. **Paginate `calculate_rewards`**: Accept a `max_iterations` parameter and allow partial reward claims, storing the updated `entry_to_claim_from` between calls.
2. **Cap balance-change frequency**: Enforce that a pool member can only add one trace entry per epoch (reject balance changes if an entry already exists for the current epoch and rewards have not been claimed).
3. **Require reward claim before balance change**: Force `claim_rewards` to be called (or auto-call it) inside `add_to_delegation_pool` and `exit_delegation_pool_intent` to keep `entry_to_claim_from` current and the loop bounded to O(1) per call.

---

### Proof of Concept

1. Pool member calls `enter_delegation_pool` to join a STRK pool.
2. Each epoch, the pool member calls `add_to_delegation_pool` with a small amount, appending a new entry to `pool_member_epoch_balance`. They never call `claim_rewards`.
3. After `N` epochs, `pool_member_epoch_balance` has `N` entries and `entry_to_claim_from == 0`.
4. `claim_rewards` is called. `calculate_rewards` enters the loop and iterates all `N` entries, each requiring a storage read (`pool_member_trace.at(i)`) and a `find_sigma` call.
5. For sufficiently large `N` (bounded only by Starknet's per-transaction gas limit), the transaction reverts out-of-gas.
6. Every subsequent call to `claim_rewards` also reverts — the pool member's yield is permanently frozen.
7. `pool_member_info_v1` also reverts for the same reason, making the member's state unreadable on-chain.

### Citations

**File:** src/pool/pool.cairo (L107-109)
```text
        /// Map pool member to their epoch-balance info.
        pool_member_epoch_balance: Map<ContractAddress, PoolMemberBalanceTrace>,
        /// Map version to class hash of the contract.
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

**File:** src/pool/pool.cairo (L349-355)
```text
            let (mut rewards, updated_entry_to_claim_from) = self
                .calculate_rewards(
                    :pool_member,
                    from_checkpoint: pool_member_info.reward_checkpoint,
                    :until_checkpoint,
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
```

**File:** src/pool/pool.cairo (L358-359)
```text
            pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
            pool_member_info.reward_checkpoint = until_checkpoint;
```

**File:** src/pool/pool.cairo (L455-464)
```text
                    // Update the pool member's balance checkpoint.
                    self.increase_member_balance(:pool_member, :amount);
                    VInternalPoolMemberInfoTrait::wrap_latest(value: pool_member_info)
                },
                Option::None => {
                    // Pool member does not exist. Create a new record.
                    let reward_address = switch_pool_data.reward_address;

                    // Update the pool member's balance checkpoint.
                    self.set_member_balance(:pool_member, :amount);
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
