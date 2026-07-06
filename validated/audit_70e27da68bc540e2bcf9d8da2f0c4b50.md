### Title
Unbounded Loop in `calculate_rewards` Permanently Freezes Pool Member Unclaimed Yield - (File: `src/pool/pool.cairo`)

---

### Summary

`claim_rewards` in the Pool contract calls `calculate_rewards`, which contains an explicitly acknowledged unbounded loop over a pool member's `pool_member_epoch_balance` trace. A pool member who accumulates enough balance-change entries without claiming can cause `claim_rewards` to always revert due to gas exhaustion, permanently freezing their unclaimed yield.

---

### Finding Description

`claim_rewards` (pool.cairo line 335) calls `calculate_rewards` (pool.cairo line 837), which iterates over every entry in the pool member's `pool_member_epoch_balance` trace that has not yet been processed:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch {
        break;
    }
    let to_sigma = self.find_sigma(pool_member_checkpoint, curr_epoch: until_epoch);
    ...
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

The `entry_to_claim_from` cursor is stored in `pool_member_info` and is only advanced when `claim_rewards` succeeds. Each call to `add_to_delegation_pool` or `exit_delegation_pool_intent` in a new epoch appends a new entry to the trace. If a pool member makes many balance changes across many epochs without ever claiming, the unprocessed portion of the trace grows without bound.

Inside the loop, `find_sigma` is called for every entry: [2](#0-1) 

`find_sigma` itself calls `find_sigma_standard_case` (pool.cairo line 928), which performs a scan over the `cumulative_rewards_trace`. The cumulative rewards trace grows by one entry per epoch. This makes the total gas cost of `calculate_rewards` O(N × M), where N is the number of unprocessed balance-change entries and M is the length of the cumulative rewards trace — both of which grow over time. [3](#0-2) 

The `claim_rewards` function is the only path to collect pool member rewards: [4](#0-3) 

Access control allows the pool member or their reward address to call it: [5](#0-4) 

---

### Impact Explanation

Once the trace is large enough that `calculate_rewards` exceeds the Starknet block gas limit, `claim_rewards` will always revert. The pool member's accumulated rewards are permanently locked in the contract with no alternative withdrawal path. This matches the allowed impact: **permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

The pool member controls the growth rate of their own trace by choosing how often to change their balance across epochs. The exit wait window (at least K epochs) limits rapid cycling, but over a long-running protocol with many epochs, a pool member who regularly adjusts their delegation without claiming will naturally accumulate a large trace. The compounding O(N × M) cost (balance trace × cumulative rewards trace) means the gas limit is reached sooner than the developers' comment "unlikely to exceed gas limits" implies, especially as the protocol matures and the cumulative rewards trace grows long.

---

### Recommendation

1. **Enforce a claim before balance changes**: Require `claim_rewards` to be called (or auto-called) before any balance change that would append to the trace, keeping `entry_to_claim_from` always close to the current trace head.
2. **Paginate `claim_rewards`**: Accept a `max_entries` parameter so the loop processes a bounded number of entries per call, allowing incremental claiming.
3. **Cap trace growth**: Enforce a maximum number of unprocessed balance-change entries per pool member, reverting new balance changes if the cap is reached.

---

### Proof of Concept

1. Pool member `A` joins a pool and makes one balance change per epoch (e.g., calls `add_to_delegation_pool` with a small additional amount each epoch) for `N` epochs without ever calling `claim_rewards`.
2. After `N` epochs, `pool_member_epoch_balance` for `A` has `N` unprocessed entries.
3. The cumulative rewards trace has grown to length `M` (one entry per epoch).
4. `A` (or their reward address) calls `claim_rewards`.
5. `calculate_rewards` enters the while-loop and iterates `N` times, calling `find_sigma` (which scans up to `M` entries) on each iteration.
6. Total storage reads ≈ O(N × M). For sufficiently large N and M, this exceeds the block gas limit and the transaction reverts.
7. Every subsequent call to `claim_rewards` for `A` also reverts — `A`'s unclaimed yield is permanently frozen. [6](#0-5)

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

**File:** src/pool/pool.cairo (L897-933)
```text
        fn find_sigma(
            self: @ContractState, pool_member_checkpoint: PoolMemberCheckpoint, curr_epoch: Epoch,
        ) -> Amount {
            let pool_member_checkpoint_epoch = pool_member_checkpoint.epoch();
            assert!(
                pool_member_checkpoint_epoch <= curr_epoch,
                "{}",
                InternalError::INVALID_EPOCH_IN_TRACE,
            );
            let cumulative_rewards_trace_vec = self.cumulative_rewards_trace;
            let cumulative_rewards_trace_idx = pool_member_checkpoint
                .cumulative_rewards_trace_idx();

            // **Reminder**:
            // Let `len` be the length of `cumulative_rewards_trace_vec` at the time the checkpoint
            // is written.
            // In old version: `cumulative_rewards_trace_idx` = `len`.
            // In this version: `cumulative_rewards_trace_idx` = `len + 1`.
            // For current checkpoint in both versions: `cumulative_rewards_trace_idx` = `len - 1`.
            // **Invariant**:
            // 1. `cumulative_rewards_trace_vec.length() >= 1`.
            // 2. `cumulative_rewards_trace_vec.length()` is only increased, never decreased.
            if let Some(sigma) =
                find_sigma_edge_cases(
                    :cumulative_rewards_trace_vec,
                    :cumulative_rewards_trace_idx,
                    target_epoch: pool_member_checkpoint_epoch,
                ) {
                return sigma;
            }

            find_sigma_standard_case(
                :cumulative_rewards_trace_vec,
                :cumulative_rewards_trace_idx,
                target_epoch: pool_member_checkpoint_epoch,
            )
        }
```
