### Title
Unbounded `calculate_rewards` Loop Enables Permanent Freezing of Pool Member's Unclaimed Yield — (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` function in the Pool contract contains an explicitly unbounded loop over a pool member's balance-change history. A pool member who makes balance adjustments across many epochs without claiming rewards can grow this trace until `claim_rewards` runs out of gas, permanently freezing their unclaimed yield.

---

### Finding Description

In `src/pool/pool.cairo`, the `calculate_rewards` function iterates over every entry in `pool_member_epoch_balance` since the last claim:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch {
        break;
    }
    ...
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

The `pool_member_epoch_balance` trace grows by one entry per epoch whenever any of the following are called:

- `enter_delegation_pool` → `set_member_balance` [2](#0-1) 
- `add_to_delegation_pool` → `increase_member_balance` [3](#0-2) 
- `exit_delegation_pool_intent` → `set_member_balance` [4](#0-3) 
- `enter_delegation_pool_from_staking_contract` → `set_member_balance` / `increase_member_balance` [5](#0-4) 

Each call inserts at key `current_epoch + K`. Because the key advances every epoch, a pool member who adjusts their delegation once per epoch accumulates one new trace entry per epoch. [6](#0-5) 

The `entry_to_claim_from` cursor stored in `pool_member_info` is only advanced when `calculate_rewards` is called (i.e., during `claim_rewards` or `pool_member_info_v1`). [7](#0-6) 

If a pool member makes balance changes every epoch but never claims rewards, the loop length grows linearly with the number of epochs elapsed. After enough epochs, the `claim_rewards` transaction will exceed Starknet's per-transaction gas limit, making it permanently impossible to claim the accumulated yield.

There is no cap on the number of entries in `pool_member_epoch_balance`, and no protocol-level mechanism forces periodic reward claims.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Once the `pool_member_epoch_balance` trace is large enough that `calculate_rewards` exhausts the transaction gas limit, the pool member can never successfully call `claim_rewards`. Their accumulated STRK rewards are permanently locked in the pool contract with no recovery path, because `entry_to_claim_from` can only advance inside the same loop that is now out-of-gas.

---

### Likelihood Explanation

**Medium.** The protocol is designed to run for years. A pool member who regularly adjusts their delegation (partial exits and re-entries, or switches) across hundreds of epochs without claiming rewards will naturally accumulate a large trace. This can occur without malicious intent — a delegator who is inattentive to reward claims but active in rebalancing their stake. An adversary who controls their own pool-member address can also deliberately trigger this state to demonstrate the issue.

---

### Recommendation

1. **Enforce a maximum trace length** by capping the number of unclaimed balance-change entries (e.g., reject new balance changes if `pool_member_trace_length - entry_to_claim_from` exceeds a safe bound, or auto-claim rewards before inserting a new entry).
2. **Batch-claim with a limit**: allow `claim_rewards` to accept a `max_iterations` parameter so it can make partial progress and resume in subsequent transactions, updating `entry_to_claim_from` after each partial run.
3. **Periodic forced settlement**: require that rewards are claimed (or at least `entry_to_claim_from` is advanced) before any new balance change is recorded, keeping the pending window bounded.

---

### Proof of Concept

1. Pool member `A` calls `enter_delegation_pool` in epoch `E`.
2. Each subsequent epoch, `A` calls `exit_delegation_pool_intent(amount=X)` followed by `add_to_delegation_pool(amount=X)`. Each pair inserts one new entry into `pool_member_epoch_balance` at `current_epoch + K`.
3. `A` never calls `claim_rewards`, so `entry_to_claim_from` stays at 0.
4. After `N` epochs, `pool_member_trace_length == N`. The `calculate_rewards` loop must execute `N` iterations, each performing multiple storage reads (`pool_member_trace.at(i)`, `find_sigma` with `cumulative_rewards_trace` lookups).
5. When `N` is large enough to exhaust the Starknet transaction gas limit, every call to `claim_rewards` reverts. `A`'s unclaimed yield is permanently frozen. [8](#0-7)

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

**File:** src/pool/pool.cairo (L456-464)
```text
                    self.increase_member_balance(:pool_member, :amount);
                    VInternalPoolMemberInfoTrait::wrap_latest(value: pool_member_info)
                },
                Option::None => {
                    // Pool member does not exist. Create a new record.
                    let reward_address = switch_pool_data.reward_address;

                    // Update the pool member's balance checkpoint.
                    self.set_member_balance(:pool_member, :amount);
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
