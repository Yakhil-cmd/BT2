### Title
Unbounded Loop in `calculate_rewards` Over Growing `pool_member_epoch_balance` Trace Can Permanently Freeze Delegator's Unclaimed Yield — (`File: src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` internal function in `src/pool/pool.cairo` iterates over the entire `pool_member_epoch_balance` trace for a given pool member. The code itself acknowledges this with the comment: *"This loop is unbounded but unlikely to exceed gas limits."* A delegator who makes repeated balance changes across many epochs without claiming rewards will grow this trace without bound, eventually causing `claim_rewards` to exceed the Starknet gas limit and permanently freeze their unclaimed yield.

---

### Finding Description

`calculate_rewards` is called from both `claim_rewards` and `pool_member_info_v1`. It iterates from `entry_to_claim_from` to the end of the `pool_member_epoch_balance` trace:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch {
        break;
    }
    // ... reward computation ...
    entry_to_claim_from += 1;
}
```

The `pool_member_epoch_balance` trace grows by one entry per epoch in which the delegator modifies their balance. The following public entry points each call `set_member_balance` or `increase_member_balance`, which call `trace.insert(key: self.get_epoch_plus_k(), ...)`:

- `enter_delegation_pool` → `set_member_balance` (line 201)
- `add_to_delegation_pool` → `increase_member_balance` (line 242)
- `exit_delegation_pool_intent` → `set_member_balance` (line 278)
- `switch_delegation_pool` (receiving side) → `increase_member_balance` / `set_member_balance` (lines 456, 464)

The `insert` function in the trace deduplicates entries with the same epoch key (updates in place), but appends a new entry for each distinct epoch. Therefore, one balance change per epoch = one new trace entry per epoch.

The `entry_to_claim_from` cursor is only advanced when `claim_rewards` is successfully called. If a delegator makes balance changes across N epochs without claiming, the loop must iterate over all N entries on the next `claim_rewards` call.

---

### Impact Explanation

If the `pool_member_epoch_balance` trace grows large enough, the `while` loop in `calculate_rewards` will consume more gas than the Starknet block gas limit, causing every future call to `claim_rewards` to revert. The delegator's accumulated unclaimed yield becomes permanently inaccessible — matching the **"Permanent freezing of unclaimed yield"** impact category.

---

### Likelihood Explanation

A delegator who actively manages their position (e.g., topping up or partially exiting each epoch) and infrequently claims rewards will naturally accumulate trace entries. The growth rate is one entry per epoch per balance-change action. While the developers note it is "unlikely to exceed gas limits," this is an assumption that depends on epoch length and Starknet's gas limit, neither of which is fixed. An active delegator over a long protocol lifetime can reach this condition without any malicious intent. Additionally, a delegator could deliberately trigger this on themselves (e.g., to later claim a refund or dispute), making it a realistic griefing vector.

---

### Recommendation

1. **Paginated claiming**: Add a `claim_rewards_from_to(pool_member, from_idx, to_idx)` function that allows partial reward computation over a bounded range of trace entries, storing intermediate state.
2. **Limit trace growth**: In `set_member_balance`, if the last entry in the trace has the same epoch key as `get_epoch_plus_k()`, update it in place (already done), but also consider compacting old entries that have already been claimed past `entry_to_claim_from`.
3. **Enforce a maximum trace length**: Revert `add_to_delegation_pool` / `exit_delegation_pool_intent` if the trace length minus `entry_to_claim_from` exceeds a safe bound, forcing the user to claim first.

---

### Proof of Concept

1. Delegator calls `enter_delegation_pool` at epoch E₀ — trace length = 1.
2. Each subsequent epoch, delegator calls `add_to_delegation_pool` with a minimal amount (1 wei) — trace grows by 1 per epoch.
3. Delegator never calls `claim_rewards`, so `entry_to_claim_from` stays at 0.
4. After N epochs, `pool_member_trace_length = N`.
5. Delegator calls `claim_rewards` — the loop iterates N times, each iteration calling `find_sigma` (a storage read). At sufficiently large N, this exceeds the gas limit and reverts permanently.
6. All accumulated rewards are frozen; the delegator cannot exit cleanly either, since `exit_delegation_pool_action` does not claim rewards but `claim_rewards` is now bricked. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** src/pool/pool.cairo (L335-377)
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
            pool_member_info.reward_checkpoint = until_checkpoint;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());

            // Emit event.
            self
                .emit(
                    Events::PoolMemberRewardClaimed {
                        pool_member, reward_address, amount: rewards,
                    },
                );

            rewards
        }
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

**File:** src/pool/pool.cairo (L734-739)
```text
        fn increase_member_balance(
            ref self: ContractState, pool_member: ContractAddress, amount: Amount,
        ) -> Amount {
            let current_balance = self.get_last_member_balance(:pool_member);
            self.set_member_balance(:pool_member, amount: current_balance + amount);
            current_balance
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
