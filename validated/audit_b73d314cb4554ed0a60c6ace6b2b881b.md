### Title
Unbounded Loop Over Pool Member Balance Trace in `calculate_rewards` Can Permanently Freeze Unclaimed Yield — (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` function in the Pool contract iterates over a pool member's entire balance-change trace in a single transaction with no upper bound. The code itself acknowledges this: *"This loop is unbounded but unlikely to exceed gas limits."* A pool member who repeatedly changes their delegation balance across many epochs will grow this trace without limit. Once the trace is large enough, every call to `claim_rewards` will exceed the Starknet block gas limit and revert, permanently freezing that member's accumulated unclaimed yield.

---

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` (lines 837–888) iterates over every entry in `pool_member_epoch_balance` that falls between the member's last checkpoint and the current epoch:

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

Every time a pool member changes their delegated balance — by entering, exiting, or adjusting their delegation — a new entry is appended to `pool_member_epoch_balance`. There is no cap on the number of entries in this trace. [2](#0-1) 

`calculate_rewards` is called from the reward-claiming path. If the trace has grown large enough, the loop will consume more gas than the block gas limit allows, causing the transaction to revert unconditionally. [3](#0-2) 

There is no pagination, no partial-claim mechanism, and no checkpoint that would allow the member to process the trace in smaller batches.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Once the trace exceeds the gas threshold, `claim_rewards` reverts on every call. The pool member's accumulated rewards become permanently inaccessible. There is no administrative escape hatch: the pool member cannot split the claim, and the trace cannot be pruned.

---

### Likelihood Explanation

**Medium.**

A pool member who actively manages their delegation — increasing or decreasing their stake across many epochs — will grow the trace through entirely normal usage. The Starknet block gas limit is finite. The code's own comment acknowledges the loop is unbounded and relies on the assumption that real-world usage will not hit the limit. An adversarial pool member can deliberately trigger this against themselves (e.g., to lock yield before a pool switch dispute), or a member can reach this state inadvertently after years of active participation.

---

### Recommendation

1. **Cap trace growth**: Enforce a maximum number of entries per pool member in `pool_member_epoch_balance` (analogous to the 7 000-character cap recommended for Hats Protocol). Reject balance-change transactions that would exceed the cap.
2. **Paginated claiming**: Allow `claim_rewards` to accept a `max_entries` parameter and store the updated `entry_to_claim_from` index so the member can claim in multiple transactions.
3. **Periodic forced checkpointing**: Automatically consolidate old trace entries into a single checkpoint during each balance-change operation, bounding the number of entries that any future claim must process.

---

### Proof of Concept

1. Pool member calls `enter_delegation_pool` — first entry written to `pool_member_epoch_balance`.
2. Across `N` successive epochs, the member alternates between `add_to_delegation_pool` and partial `exit_delegation_pool_intent` + re-entry, writing one new trace entry per epoch.
3. After `N` epochs without claiming, the member calls `claim_rewards`.
4. `claim_rewards` internally calls `calculate_rewards`, which loops over all `N` entries.
5. For sufficiently large `N`, the loop exhausts the block gas limit; the transaction reverts.
6. Every subsequent `claim_rewards` call also reverts — the member's yield is permanently frozen with no recovery path. [4](#0-3)

### Citations

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
