### Title
Unbounded `pool_member_epoch_balance` Trace Growth Causes Permanent Freezing of Unclaimed Yield - (File: `src/pool/pool.cairo`)

### Summary
The `calculate_rewards` function in `pool.cairo` iterates over a pool member's entire `pool_member_epoch_balance` trace in an unbounded loop. The codebase itself acknowledges this: *"This loop is unbounded but unlikely to exceed gas limits."* A pool member who makes balance changes across many epochs without claiming rewards will accumulate a large trace. Once the trace is large enough, both `claim_rewards` and the view function `pool_member_info_v1` will revert due to gas exhaustion, permanently freezing the member's unclaimed yield.

### Finding Description

In `src/pool/pool.cairo`, the internal `calculate_rewards` function iterates over all `pool_member_epoch_balance` trace entries from `entry_to_claim_from` to the current trace length: [1](#0-0) 

The trace is keyed by `get_epoch_plus_k()` (current epoch + K). The `insert` logic in the trace only merges entries sharing the **same epoch key**; a balance change in a new epoch always appends a fresh checkpoint: [2](#0-1) 

Every call to `add_to_delegation_pool` or `exit_delegation_pool_intent` in a distinct epoch appends one new entry via `set_member_balance`: [3](#0-2) 

The `entry_to_claim_from` pointer (stored in `pool_member_info`) advances only when `claim_rewards` is called. A delegator who makes balance changes across N epochs without claiming will force the loop to iterate over all N entries on the next claim attempt.

The same unbounded `calculate_rewards` call is also made inside the **view function** `pool_member_info_v1`: [4](#0-3) 

So both the state-changing `claim_rewards` and the read-only `pool_member_info_v1` will revert once the trace is large enough, bricking all reward interactions for that member.

### Impact Explanation

**Permanent freezing of unclaimed yield.** Once the trace exceeds the gas limit per transaction, the pool member can no longer call `claim_rewards` (their accumulated STRK rewards are locked forever) and cannot even query their balance via `pool_member_info_v1`. There is no administrative escape hatch or trace-pruning mechanism in the contract.

### Likelihood Explanation

**Medium.** The trace grows at most one entry per epoch. However, an active long-term delegator who:
1. Regularly calls `add_to_delegation_pool` or `exit_delegation_pool_intent` across many epochs, **and**
2. Infrequently calls `claim_rewards`

...will accumulate a large trace organically. The protocol has no minimum claim frequency requirement and no cap on trace length. Over hundreds of epochs (realistic for a multi-year protocol), the trace can grow large enough to exceed Starknet's per-transaction gas limit. The codebase itself flags this risk with the comment *"This loop is unbounded but unlikely to exceed gas limits"* — acknowledging the hazard without bounding it.

### Recommendation

1. **Enforce a maximum trace depth**: Cap `pool_member_epoch_balance` entries per member (e.g., 100–200). Reject or merge balance changes that would exceed the cap.
2. **Require periodic claiming**: Enforce a maximum number of unclaimed epochs before new balance changes are accepted, similar to the 1-day epoch merging fix applied in Radiant Capital PR #201.
3. **Paginated claiming**: Allow `claim_rewards` to accept an `until_epoch` parameter so rewards can be claimed in batches, preventing a single transaction from needing to iterate the full trace.

### Proof of Concept

1. Staker stakes and opens a STRK pool.
2. Delegator calls `enter_delegation_pool` with a small amount.
3. For each of N epochs (e.g., N = 500), the delegator calls `add_to_delegation_pool` with amount = 1 (minimum non-zero). Each call in a new epoch appends one entry to `pool_member_epoch_balance` via `set_member_balance` → `insert`.
4. The delegator never calls `claim_rewards`, so `entry_to_claim_from` remains at 0.
5. After N epochs, the delegator calls `claim_rewards`. The loop at line 859 iterates all N entries, each requiring storage reads and `find_sigma` computations. At sufficiently large N, the transaction runs out of gas and reverts.
6. All subsequent calls to `claim_rewards` and `pool_member_info_v1` also revert. The delegator's accumulated STRK rewards are permanently frozen. [5](#0-4) [6](#0-5)

### Citations

**File:** src/pool/pool.cairo (L221-253)
```text
        fn add_to_delegation_pool(
            ref self: ContractState, pool_member: ContractAddress, amount: Amount,
        ) -> Amount {
            // Asserts.
            self.assert_staker_is_active();
            let pool_member_info = self.internal_pool_member_info(:pool_member);
            let caller_address = get_caller_address();
            assert!(
                caller_address == pool_member || caller_address == pool_member_info.reward_address,
                "{}",
                Error::CALLER_CANNOT_ADD_TO_POOL,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);

            // Transfer funds from the delegator to the staking contract.
            let token_dispatcher = self.token_dispatcher.read();
            let staker_address = self.staker_address.read();
            transfer_from_delegator(pool_member: caller_address, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);

            // Update the pool member's balance checkpoint.
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
            let new_delegated_stake = old_delegated_stake + amount;

            // Emit events.
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake, new_delegated_stake,
                    },
                );

            new_delegated_stake
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

**File:** src/pool/pool.cairo (L528-540)
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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L163-173)
```text
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
```
