### Title
Unbounded loop in `calculate_rewards` allows permanent freezing of delegator's unclaimed yield - (File: src/pool/pool.cairo)

### Summary
The `calculate_rewards` function in the pool contract contains an explicitly acknowledged unbounded loop over a pool member's balance trace. A delegator who makes balance changes across many epochs without claiming rewards can grow this trace unboundedly, eventually causing `claim_rewards` to run out of gas and permanently freezing their unclaimed yield.

### Finding Description
In `src/pool/pool.cairo`, the internal `calculate_rewards` function iterates over all entries in `pool_member_epoch_balance` from `entry_to_claim_from` to the current trace length. The developers themselves flag this at lines 857–858:

> "This loop is unbounded but unlikely to exceed gas limits." [1](#0-0) 

Every time a pool member changes their balance in a new epoch — via `enter_delegation_pool`, `add_to_delegation_pool`, or `exit_delegation_pool_intent` — `set_member_balance` is called, which calls `trace.insert(key: self.get_epoch_plus_k(), value: ...)`. Because the trace's `insert` only merges entries with the same key, each distinct epoch produces a new checkpoint appended to the `pool_member_epoch_balance` Vec. [2](#0-1) 

The `entry_to_claim_from` cursor that bounds the loop is only advanced inside a successful `claim_rewards` call: [3](#0-2) 

If the pool member never calls `claim_rewards`, `entry_to_claim_from` stays at its initial value while the trace grows by one entry per epoch in which a balance change occurs. After N such epochs the loop must traverse N entries. Starknet transactions have a finite gas ceiling; once N is large enough the call reverts unconditionally.

The same unbounded loop is also executed (read-only) inside `pool_member_info_v1`, which is callable by anyone: [4](#0-3) 

### Impact Explanation
When `claim_rewards` runs out of gas, the transaction reverts without updating `entry_to_claim_from` or `reward_checkpoint`. Every subsequent call to `claim_rewards` starts from the same position and hits the same gas wall. There is no partial-claim mechanism and no way to truncate or reset the trace. The delegator's entire accumulated unclaimed yield is permanently inaccessible — matching the **High: Permanent freezing of unclaimed yield** impact class.

### Likelihood Explanation
Any delegator who regularly adjusts their delegation (e.g., monthly top-ups via `add_to_delegation_pool`) and infrequently claims rewards will accumulate one new trace entry per epoch. Starknet epochs are short (on the order of hours to days). A delegator who tops up weekly and claims annually could accumulate hundreds of entries per year. The Starknet per-transaction gas limit is finite; at sufficient scale the loop will exceed it. This is a realistic long-term usage pattern, not a contrived edge case.

### Recommendation
1. **Introduce a partial-claim mechanism**: allow `claim_rewards` to accept an `until_epoch` parameter so the loop is bounded per call.
2. **Cap unclaimed epochs**: revert or warn if `current_epoch - reward_checkpoint.epoch` exceeds a safe threshold (e.g., 500 epochs), forcing periodic claims.
3. **Prune the trace on claim**: after advancing `entry_to_claim_from`, compact or drop the consumed prefix of `pool_member_epoch_balance` so the live window never grows without bound.

### Proof of Concept
1. Delegator calls `enter_delegation_pool` in epoch `E`, creating the first trace entry at epoch `E + K`.
2. In each subsequent epoch `E+i`, the delegator calls `add_to_delegation_pool` with a minimal amount (e.g., 1 token). Each call invokes `increase_member_balance` → `set_member_balance` → `trace.insert(key: E+i+K, ...)`, appending a distinct entry because `E+i+K ≠ E+j+K` for `i ≠ j`.
3. The delegator never calls `claim_rewards`, so `entry_to_claim_from` remains `0`.
4. After `N` epochs the trace contains `N` entries.
5. The delegator (or their reward address) calls `claim_rewards`. `calculate_rewards` enters the `while entry_to_claim_from < pool_member_trace_length` loop and must read and process all `N` entries. For sufficiently large `N` the transaction runs out of gas and reverts.
6. Because the revert leaves `entry_to_claim_from = 0` and `reward_checkpoint` unchanged, every future call to `claim_rewards` repeats step 5 and also reverts. The delegator's unclaimed yield is permanently frozen.

### Citations

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
