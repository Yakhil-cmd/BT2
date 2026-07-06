### Title
Unbounded Loop Over `pool_member_epoch_balance` Trace in `calculate_rewards` Can Permanently Freeze Pool Member's Unclaimed Yield — (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` internal function in `pool.cairo` iterates over every entry in a pool member's `pool_member_epoch_balance` trace that has not yet been accounted for. Because this trace grows by one entry each epoch in which the member changes their balance, a sufficiently active pool member will eventually accumulate a trace large enough to cause `claim_rewards` (and `pool_member_info_v1`) to exceed the Starknet per-transaction gas limit, permanently freezing their unclaimed yield. The developers themselves flag this in a code comment.

---

### Finding Description

`pool_member_epoch_balance` is a per-member `PoolMemberBalanceTrace` stored in contract storage. Every call to `set_member_balance` appends a new checkpoint keyed at `current_epoch + K`: [1](#0-0) 

This is invoked by:
- `enter_delegation_pool` → `set_member_balance`
- `add_to_delegation_pool` → `increase_member_balance` → `set_member_balance`
- `exit_delegation_pool_intent` → `set_member_balance`
- `enter_delegation_pool_from_staking_contract` (pool switch) → `set_member_balance` or `increase_member_balance`

Each call in a distinct epoch appends a new entry. Over time, the trace length grows proportionally to the number of epochs in which the member was active.

`calculate_rewards` then iterates over every unprocessed entry in this trace: [2](#0-1) 

The developers explicitly acknowledge the risk in a comment at line 858:

> `// **Note**: The loop iterates over the balance changes in the pool member's balance trace. This loop is unbounded but unlikely to exceed gas limits.` [3](#0-2) 

`calculate_rewards` is called from `claim_rewards`: [4](#0-3) 

and from the view function `pool_member_info_v1`: [5](#0-4) 

The `entry_to_claim_from` cursor stored in `pool_member_info` advances after each successful `claim_rewards`, so the loop only covers entries since the last claim. A member who makes one balance change per epoch for N epochs without claiming will face a loop of N iterations on their next `claim_rewards` call.

---

### Impact Explanation

When the trace is large enough, `claim_rewards` reverts with an out-of-gas error on every attempt. Because `entry_to_claim_from` is only updated inside a successful `claim_rewards` execution, the cursor never advances, and the member can never reduce the loop length. Their accumulated STRK rewards are permanently locked in the pool contract with no recovery path.

**Impact class**: Permanent freezing of unclaimed yield — **High** per the allowed impact scope.

---

### Likelihood Explanation

A pool member who participates actively across many epochs (e.g., adjusting delegation size each epoch, or repeatedly switching pools) will naturally accumulate a large trace. Starknet enforces a hard per-transaction gas/step limit. At a rate of one balance change per epoch, a member active for several hundred epochs without claiming will hit the limit. This is a realistic scenario for long-term delegators who prefer to compound manually or who use automated strategies that adjust stake frequently.

---

### Recommendation

1. **Paginated claiming**: Introduce a `claim_rewards_up_to(max_entries: VecIndex)` variant that processes at most `max_entries` trace entries per call, advancing `entry_to_claim_from` incrementally. This lets a member drain a large trace over multiple transactions.
2. **Enforce a claim cadence**: Require or incentivize members to claim (or auto-checkpoint) at least once every fixed number of epochs, bounding the maximum loop length.
3. **Trace compaction**: After a successful `claim_rewards`, truncate or compact the already-processed prefix of `pool_member_epoch_balance` so the trace does not grow without bound.

---

### Proof of Concept

1. Deploy the staking + pool contracts.
2. A pool member calls `enter_delegation_pool` in epoch 0.
3. For epochs 1 through N (e.g., N = 1000), the member calls `add_to_delegation_pool` with a minimal amount once per epoch, never calling `claim_rewards`. Each call appends one entry to `pool_member_epoch_balance`.
4. After epoch N, the member calls `claim_rewards`. `calculate_rewards` enters the `while` loop and iterates N times, each iteration reading from storage (`pool_member_trace.at(entry_to_claim_from)`) and calling `find_sigma`.
5. For sufficiently large N, the transaction exceeds Starknet's step/gas limit and reverts.
6. Every subsequent `claim_rewards` attempt also reverts because `entry_to_claim_from` was never updated. The member's accumulated rewards are permanently frozen. [6](#0-5) [7](#0-6)

### Citations

**File:** src/pool/pool.cairo (L221-254)
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
        }
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

**File:** src/pool/pool.cairo (L532-538)
```text
            let (rewards, _) = self
                .calculate_rewards(
                    :pool_member,
                    from_checkpoint: pool_member_info.reward_checkpoint,
                    until_checkpoint: self.get_current_checkpoint(:pool_member),
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
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
