### Title
Unbounded Loop in `calculate_rewards` Can Permanently Freeze Pool Member's Unclaimed Yield - (File: src/pool/pool.cairo)

---

### Summary
The `calculate_rewards` function in `pool.cairo` contains an explicitly acknowledged unbounded loop that iterates over a pool member's entire balance-change history since their last reward claim. A pool member who accumulates balance-change entries across many epochs without claiming rewards will eventually be unable to call `claim_rewards` due to gas/step exhaustion, permanently freezing their unclaimed yield.

---

### Finding Description

In `src/pool/pool.cairo`, the `calculate_rewards` function contains a `while` loop that iterates over every entry in the pool member's `pool_member_epoch_balance` trace from `entry_to_claim_from` up to `pool_member_trace_length`. The code itself contains the comment:

> "**Note**: The loop iterates over the balance changes in the pool member's balance trace. This loop is unbounded but unlikely to exceed gas limits." [1](#0-0) 

Every call to `add_to_delegation_pool` or `exit_delegation_pool_intent` triggers `set_member_balance`, which inserts a new checkpoint into the pool member's balance trace at key `current_epoch + K` (K=2 per `src/constants.cairo`). [2](#0-1) [3](#0-2) 

Since each epoch produces at most one distinct key, the trace grows by at most one entry per epoch. The `entry_to_claim_from` cursor is stored in `pool_member_info.entry_to_claim_from` and is only advanced when `claim_rewards` successfully completes. [4](#0-3) 

If a pool member participates in balance changes across many epochs without ever calling `claim_rewards`, the number of unclaimed entries accumulates without bound. When `claim_rewards` is eventually called, it invokes `calculate_rewards` which must iterate over all accumulated entries. If the count is large enough to exceed Starknet's per-transaction step limit, the transaction reverts. Because there is no partial-claim mechanism and no way to advance `entry_to_claim_from` independently, the pool member's accumulated yield becomes permanently unclaimable.

---

### Impact Explanation

A pool member who has been active across many epochs without claiming rewards will have their `claim_rewards` call permanently revert. There is no alternative code path to retrieve the yield. This constitutes **permanent freezing of unclaimed yield**, which is within the allowed impact scope.

---

### Likelihood Explanation

The likelihood scales with epoch count since last claim and epoch duration. If epochs are short (e.g., days) and a pool member is inactive for years, hundreds to thousands of trace entries accumulate. The developers themselves flag this risk in the inline comment at line 858. No privileged access is required; any delegator can reach this state organically by simply not calling `claim_rewards` for an extended period while continuing to adjust their delegation balance each epoch.

---

### Recommendation

1. Introduce a maximum cap on the number of balance-trace entries that can accumulate before a claim is required (e.g., enforce a claim every N epochs).
2. Implement a paginated/partial `claim_rewards` that accepts a `max_entries` parameter, allowing the pool member to claim in batches and advance `entry_to_claim_from` incrementally.
3. Prune or merge old trace entries that are no longer needed for reward computation after they have been processed.

---

### Proof of Concept

1. Pool member calls `enter_delegation_pool` and then alternates between `add_to_delegation_pool` and `exit_delegation_pool_intent` across many epochs, generating one new trace entry per epoch via `set_member_balance`.
2. Pool member never calls `claim_rewards`, so `entry_to_claim_from` remains at 0 while `pool_member_trace_length` grows by 1 each epoch.
3. After sufficiently many epochs (exact threshold depends on Starknet's per-transaction step limit), the pool member calls `claim_rewards`.
4. `claim_rewards` → `calculate_rewards` → the `while` loop at line 859 iterates over all accumulated entries and exceeds the step limit.
5. The transaction reverts. Every subsequent retry produces the same revert. The pool member's unclaimed yield is permanently frozen with no recovery path. [5](#0-4) [6](#0-5)

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

**File:** src/constants.cairo (L13-13)
```text
pub(crate) const K: u8 = 2;
```
