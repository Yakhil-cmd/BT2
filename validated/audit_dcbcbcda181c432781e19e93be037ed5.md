### Title
Unbounded Loop in `calculate_rewards` Can Permanently Freeze Delegator's Unclaimed Yield — (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` internal function in the Pool contract contains an explicitly acknowledged unbounded loop over a pool member's `pool_member_epoch_balance` trace. A delegator who repeatedly changes their delegated balance without claiming rewards accumulates trace entries without bound. Once the trace grows large enough, the gas cost of iterating through it in a single `claim_rewards` transaction exceeds Starknet's transaction gas limit, permanently bricking the delegator's ability to claim their accrued yield.

---

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` is the core reward computation routine called by `claim_rewards`. It iterates over every entry in the pool member's `pool_member_epoch_balance` trace that has not yet been accounted for since the last claim:

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

The developers themselves flag this as "unbounded but unlikely to exceed gas limits." The trace (`pool_member_epoch_balance`) is a `Vec<PoolMemberBalanceCheckpoint>` that grows by one entry every time the pool member's balance changes (i.e., on every `enter_delegation_pool`, `increase_delegate`, `exit_intent`, or `switch_delegation_pool` call). [2](#0-1) 

The `entry_to_claim_from` cursor in `pool_member_info` advances only when `claim_rewards` is successfully called:

```cairo
pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
``` [3](#0-2) 

If a delegator never calls `claim_rewards` (or calls it infrequently) while repeatedly changing their balance, the gap between `entry_to_claim_from` and `pool_member_trace_length` grows without bound. When the delegator eventually calls `claim_rewards`, the loop must traverse every accumulated entry in a single transaction. Once the entry count is large enough, the transaction runs out of gas and reverts. Because the cursor is only advanced on a successful claim, every subsequent attempt also fails — the delegator's unclaimed yield is permanently frozen.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

A delegator who has accumulated a sufficiently large balance trace can never successfully call `claim_rewards`. Their accrued STRK rewards are locked in the pool contract forever with no recovery path short of a contract upgrade. This matches the allowed impact: *"Permanent freezing of unclaimed yield or unclaimed royalties."*

---

### Likelihood Explanation

**Medium.** The scenario requires a delegator to make many balance-changing calls without claiming rewards. This is realistic for:

- Active delegators who frequently adjust their delegation size (e.g., dollar-cost averaging in/out) without claiming between adjustments.
- Delegators who switch pools repeatedly, each switch generating trace entries.
- Long-lived delegators who simply forget to claim for many epochs while continuing to adjust their stake.

The developers' own comment — *"This loop is unbounded but unlikely to exceed gas limits"* — confirms awareness of the risk but provides no enforcement mechanism to prevent it. [4](#0-3) 

---

### Recommendation

1. **Enforce periodic claims**: Require `claim_rewards` to be called (or auto-claim) before any balance-changing operation, keeping `entry_to_claim_from` always close to the trace head.
2. **Bound the loop**: Process at most `MAX_ENTRIES_PER_CLAIM` entries per call and allow partial claims, so a delegator can drain the backlog over multiple transactions.
3. **Merge same-epoch entries**: Prevent multiple trace entries from accumulating within the same epoch by updating the existing entry in place rather than appending a new one.

---

### Proof of Concept

1. Delegator calls `enter_delegation_pool` — trace length = 1, `entry_to_claim_from` = 0.
2. Delegator calls `increase_delegate` N times across N different epochs without ever calling `claim_rewards` — trace length = N+1, `entry_to_claim_from` = 0.
3. Delegator calls `claim_rewards`. The loop in `calculate_rewards` must iterate over all N+1 entries.
4. For sufficiently large N (on the order of Starknet's per-transaction gas limit divided by the per-iteration cost), the transaction runs out of gas and reverts.
5. `entry_to_claim_from` is never updated. Every future `claim_rewards` call also reverts. The delegator's yield is permanently frozen.

The entry path is entirely unprivileged: `claim_rewards` is callable by the pool member or their reward address. [5](#0-4) [6](#0-5)

### Citations

**File:** src/pool/pool.cairo (L335-344)
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
```

**File:** src/pool/pool.cairo (L358-359)
```text
            pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
            pool_member_info.reward_checkpoint = until_checkpoint;
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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L9-14)
```text
/// `Trace` struct, for checkpointing values as they change at different points in
/// time, and later looking up past values by block timestamp.
#[starknet::storage_node]
pub struct PoolMemberBalanceTrace {
    checkpoints: Vec<PoolMemberBalanceCheckpoint>,
}
```
