### Title
Unbounded Loop in `calculate_rewards` Can Permanently Freeze Delegator's Unclaimed Yield - (File: `src/pool/pool.cairo`)

### Summary
The `calculate_rewards` internal function in `Pool` iterates over every balance-change checkpoint in a pool member's epoch-balance trace without any upper bound. The code itself acknowledges this: *"This loop is unbounded but unlikely to exceed gas limits."* A delegator who accumulates many balance-change epochs without claiming rewards will eventually be unable to call `claim_rewards` because the loop will exhaust the transaction gas limit, permanently freezing their unclaimed yield.

### Finding Description
`calculate_rewards` is called by `claim_rewards` to compute how much STRK a pool member is owed since their last claim. It does so by iterating over every entry in `pool_member_epoch_balance` (the per-member balance trace) from `entry_to_claim_from` up to the current epoch:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    ...
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

Every time a pool member changes their delegated balance — via `enter_delegation_pool`, `increase_delegate`, `exit_delegation_pool_intent`, or `switch_delegation_pool` — a new checkpoint is appended to their trace for that epoch. If a delegator makes balance changes across N distinct epochs without ever calling `claim_rewards`, the trace accumulates N entries. The `entry_to_claim_from` cursor only advances after a *successful* claim:

```cairo
pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
``` [2](#0-1) 

Once the trace is large enough that a single `claim_rewards` call cannot iterate through all pending entries within the Starknet transaction gas limit, the call reverts. Because the cursor is only updated on success, every subsequent attempt starts from the same position and also reverts. The delegator's accumulated rewards are permanently inaccessible.

`claim_rewards` is the sole on-chain path to retrieve pool member rewards:

```cairo
fn claim_rewards(ref self: ContractState, pool_member: ContractAddress) -> Amount {
    ...
    let (mut rewards, updated_entry_to_claim_from) = self
        .calculate_rewards(
            :pool_member,
            from_checkpoint: pool_member_info.reward_checkpoint,
            :until_checkpoint,
            entry_to_claim_from: pool_member_info.entry_to_claim_from,
        );
``` [3](#0-2) 

There is no partial-claim or paginated variant of `claim_rewards` that would allow the delegator to process a bounded slice of the trace per transaction.

### Impact Explanation
A delegator whose trace grows beyond the gas-processable limit can never successfully call `claim_rewards`. All STRK rewards accrued since their last successful claim are permanently frozen in the pool contract. This matches the **High** impact category: *Permanent freezing of unclaimed yield*.

### Likelihood Explanation
Any unprivileged delegator who:
1. Delegates to a pool,
2. Repeatedly changes their delegated amount (increase, partial exit-intent + re-enter, switch) across many distinct epochs, and
3. Does not call `claim_rewards` between those changes,

will grow their trace. The protocol imposes no maximum on how many epochs a delegator may go without claiming, and no cap on the number of balance-change entries. Over a sufficiently long participation period (hundreds of epochs), the trace can grow large enough to trigger the gas limit. This is a realistic scenario for long-term, active delegators.

### Recommendation
1. **Paginate `claim_rewards`**: Accept an optional `max_entries` parameter so the caller can process a bounded slice of the trace per transaction, updating `entry_to_claim_from` and `reward_checkpoint` atomically after each partial run.
2. **Alternatively**, add a standalone `claim_rewards(pool_member, start, end)` overload that processes only the entries in `[start, end)`, allowing callers to drain the trace in multiple transactions.
3. **Enforce a maximum trace depth** by requiring delegators to claim before making a new balance change once the trace exceeds a threshold.

### Proof of Concept
```
// Pseudocode — illustrates the growth path
for epoch in 1..=N {
    advance_epoch();
    increase_delegate(delegator, pool, small_amount); // appends one trace entry per epoch
    // deliberately skip claim_rewards
}
// After N epochs, pool_member_epoch_balance.length() == N
// claim_rewards now iterates N times inside calculate_rewards
// For large N, this exceeds the Starknet tx gas limit → permanent revert
claim_rewards(pool_member: delegator); // FAILS with out-of-gas
```

The root cause is at: [1](#0-0) 

called unconditionally from: [4](#0-3)

### Citations

**File:** src/pool/pool.cairo (L335-358)
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

            let until_checkpoint = self.get_current_checkpoint(:pool_member);

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
