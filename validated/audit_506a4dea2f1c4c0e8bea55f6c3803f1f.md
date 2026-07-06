### Title
Unbounded Loop in `calculate_rewards` Over Growing `pool_member_epoch_balance` Trace Can Permanently Freeze Pool Member's Unclaimed Yield - (File: src/pool/pool.cairo)

### Summary
The `calculate_rewards` function in `Pool` iterates over every entry in a pool member's `pool_member_epoch_balance` trace since their last claim. Because each call to `add_to_delegation_pool` or `exit_delegation_pool_intent` in a new epoch appends a new checkpoint to this trace, a pool member who makes frequent balance changes without claiming rewards will accumulate an unbounded trace. When they eventually call `claim_rewards`, the loop must process all accumulated entries and can exceed the Starknet transaction gas limit, permanently freezing their unclaimed yield.

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` contains an explicit unbounded loop:

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
``` [1](#0-0) 

The loop starts at `entry_to_claim_from` (the index saved from the last `claim_rewards` call) and runs to `pool_member_trace_length`. The trace grows via `set_member_balance`, which calls `trace.insert(key: self.get_epoch_plus_k(), ...)`: [2](#0-1) 

The `insert` implementation only updates the last entry if the key matches; otherwise it **appends** a new checkpoint: [3](#0-2) 

This means every call to `add_to_delegation_pool` or `exit_delegation_pool_intent` in a **different epoch** appends a new entry. Since `entry_to_claim_from` only advances when `claim_rewards` is called: [4](#0-3) 

a pool member who makes N balance changes across N distinct epochs without ever claiming rewards will force the loop to iterate N times on the next `claim_rewards` call. Each iteration also invokes `find_sigma`, adding further per-iteration cost.

`calculate_rewards` is called both from `claim_rewards` and from the view function `pool_member_info_v1`: [5](#0-4) 

### Impact Explanation

If the trace grows large enough that the gas cost of iterating it exceeds the Starknet per-transaction gas limit, every call to `claim_rewards` for that pool member will revert. Since `entry_to_claim_from` is never advanced on a revert, the pool member is permanently unable to claim their accrued yield. Their principal remains accessible via `exit_delegation_pool_action` (which does not call `calculate_rewards`), but all accumulated unclaimed rewards are frozen forever.

**Impact: High — Permanent freezing of unclaimed yield.**

### Likelihood Explanation

The scenario requires a pool member to make balance changes in many distinct epochs without claiming rewards. This is realistic for:
- A long-term delegator who adds small amounts frequently (e.g., auto-compounding bots that call `add_to_delegation_pool` each epoch) but defers reward claims.
- A pool member who is unaware of the gas accumulation risk.

The trace grows at a rate of at most 1 entry per epoch. Starknet epochs are on the order of days, so over months to years of active participation without claiming, the trace can reach thousands of entries. The developers themselves acknowledge the risk in a code comment: *"This loop is unbounded but unlikely to exceed gas limits."*

**Likelihood: Medium** — requires sustained inactivity in claiming combined with frequent balance changes, but is a realistic long-term operational pattern.

### Recommendation

Track `entry_to_claim_from` as a high-water mark and enforce a maximum number of trace entries processed per `claim_rewards` call (partial claiming). Alternatively, compress the trace on each `claim_rewards` by deleting all processed entries up to `entry_to_claim_from`, or require pool members to claim rewards before making additional balance changes if the unclaimed trace depth exceeds a threshold.

### Proof of Concept

1. Pool member Alice calls `enter_delegation_pool` at epoch E₀. One entry is appended to her `pool_member_epoch_balance` trace.
2. Alice calls `add_to_delegation_pool` once per epoch for 10,000 epochs (E₁ … E₁₀₀₀₀), never calling `claim_rewards`. Each call in a new epoch appends a new entry; her trace now has 10,001 entries and `entry_to_claim_from` is still 0.
3. Alice calls `claim_rewards`. `calculate_rewards` is invoked with `entry_to_claim_from = 0` and `pool_member_trace_length = 10,001`. The loop iterates 10,001 times, each iteration reading a storage slot and calling `find_sigma`. The transaction runs out of gas and reverts.
4. All subsequent `claim_rewards` calls also revert. Alice's accumulated yield is permanently frozen. [6](#0-5) [7](#0-6)

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
