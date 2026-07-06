### Title
Unbounded loop in `calculate_rewards` over pool member balance trace enables permanent freezing of unclaimed yield — (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` function in the Pool contract contains an explicitly unbounded `while` loop that iterates over a delegator's entire balance-change history since their last reward claim. Because there is no cap on how many entries a delegator can accumulate in their `pool_member_epoch_balance` trace, a delegator who repeatedly changes their balance across epochs without claiming rewards will grow this trace without bound. Once the trace is large enough, every call to `claim_rewards` will exceed the Starknet transaction gas limit, permanently freezing the delegator's (or their reward address's) unclaimed yield.

---

### Finding Description

**Root cause — `src/pool/pool.cairo` lines 857–877:**

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch {
        break;
    }
    let to_sigma = self.find_sigma(pool_member_checkpoint, curr_epoch: until_epoch);
    rewards += compute_rewards_rounded_down(...);
    from_sigma = to_sigma;
    from_balance = pool_member_checkpoint.balance();
    entry_to_claim_from += 1;
}
```

The code itself acknowledges the loop is unbounded. [1](#0-0) 

**How the trace grows:**

`set_member_balance` inserts a new checkpoint at `current_epoch + K` into the `pool_member_epoch_balance` Vec. The `insert` function in the trace only *updates* the last entry if the key (epoch) is the same; otherwise it *appends* a new entry. [2](#0-1) 

This means every epoch in which a delegator calls `add_to_delegation_pool` or `exit_delegation_pool_intent` adds exactly one new entry to their trace. [3](#0-2) 

**How the cursor works:**

`claim_rewards` passes `pool_member_info.entry_to_claim_from` as the starting index and saves the updated index back to storage after the call. [4](#0-3) 

If the delegator never calls `claim_rewards`, `entry_to_claim_from` stays at `0`. After `N` epochs of balance changes, the loop must iterate over all `N` entries on the next claim.

**No cap exists anywhere.** There is no maximum on the number of entries in `pool_member_epoch_balance`, no maximum on the number of epochs between claims, and no gas-scaled fee for balance changes. [5](#0-4) 

---

### Impact Explanation

Once the trace is large enough that a single `claim_rewards` call exhausts the Starknet transaction gas limit, the delegator's unclaimed yield is permanently frozen:

- `claim_rewards` is the only mechanism to transfer accrued rewards to the reward address. [6](#0-5) 
- Because `entry_to_claim_from` only advances inside a successful `claim_rewards` call, a gas-exhausting trace can never be drained incrementally — there is no partial-claim mechanism.
- If the pool member set a separate `reward_address` (a third party), that third party's yield is permanently frozen by the pool member's behaviour, with no recourse.

**Impact class:** Permanent freezing of unclaimed yield (High).

---

### Likelihood Explanation

- The trace grows at most one entry per epoch. An attacker must sustain balance-change calls across many epochs without claiming rewards.
- Each balance-change call costs gas, so there is a cost to the attacker.
- However, a legitimate long-term delegator who frequently adjusts their position and rarely claims rewards will naturally accumulate a large trace over time — no malicious intent is required.
- There is no protocol-enforced minimum claim frequency or maximum trace depth.
- The code comment itself acknowledges the loop is unbounded and relies on an informal assumption ("unlikely to exceed gas limits") rather than a hard bound.

**Likelihood: Low** (requires sustained multi-epoch activity without claiming), but the risk is non-zero and grows monotonically with protocol age.

---

### Recommendation

Apply the same two options noted in the analogous MilkyWay fix:

1. **Cap the number of unclaimed balance-change entries per delegator** (recommended). Enforce a maximum trace depth (e.g., 100 entries) and revert `add_to_delegation_pool` / `exit_delegation_pool_intent` if the cap would be exceeded without a prior `claim_rewards`.
2. **Add a gas surcharge that scales linearly with the current unclaimed trace depth** on every balance-change call, making unbounded accumulation economically prohibitive.

---

### Proof of Concept

1. Delegator `A` enters a pool with a small amount and sets `reward_address = B` (a separate address).
2. Every epoch, `A` calls `add_to_delegation_pool(1)` — this appends one new entry to `pool_member_epoch_balance[A]` at `current_epoch + K`. `A` never calls `claim_rewards`.
3. After `N` epochs, `pool_member_epoch_balance[A]` has `N` entries and `entry_to_claim_from = 0`.
4. `B` calls `claim_rewards(pool_member: A)`. The `calculate_rewards` loop iterates from index `0` to `N-1`, calling `find_sigma` on each entry. For sufficiently large `N`, the transaction runs out of gas and reverts.
5. Because `entry_to_claim_from` was never updated (the transaction reverted), every future call to `claim_rewards` also reverts. `B`'s yield is permanently frozen.

### Citations

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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L121-124)
```text
    /// Returns the total number of checkpoints.
    fn length(self: StoragePath<PoolMemberBalanceTrace>) -> u64 {
        self.checkpoints.len()
    }
```

**File:** src/pool/pool_member_balance_trace/trace.cairo (L152-175)
```text
    fn insert(
        self: StoragePath<Mutable<PoolMemberBalanceTrace>>, key: Epoch, value: PoolMemberBalance,
    ) -> (PoolMemberBalance, PoolMemberBalance) {
        let checkpoints = self.checkpoints;

        let len = checkpoints.len();
        if len == Zero::zero() {
            checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
            return (Zero::zero(), value);
        }

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
        (prev, value)
    }
```
