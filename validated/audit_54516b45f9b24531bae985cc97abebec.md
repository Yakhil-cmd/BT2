### Title
Unbounded Loop in `calculate_rewards` Allows Permanent Freezing of Pool Member Unclaimed Yield - (File: src/pool/pool.cairo)

### Summary

The `calculate_rewards` internal function in `src/pool/pool.cairo` contains an unbounded loop that iterates over every entry in a pool member's `pool_member_epoch_balance` trace since their last claim. Because each balance change in a distinct epoch appends a new entry to this trace, a pool member who makes many balance changes across many epochs without claiming rewards will eventually cause `claim_rewards` to exceed the Starknet transaction gas limit, permanently freezing their unclaimed yield.

### Finding Description

**Root cause — unbounded loop in `calculate_rewards`:**

The function `calculate_rewards` (called exclusively from `claim_rewards`) iterates over the pool member's entire balance trace from `entry_to_claim_from` to the current epoch:

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
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

The code itself acknowledges the issue with the comment "This loop is unbounded but unlikely to exceed gas limits."

**How the trace grows:**

Every call to `set_member_balance` inserts a checkpoint keyed by `get_epoch_plus_k()` (current epoch + K). The trace insert logic only appends a new entry when the key (epoch) differs from the last entry; same-epoch updates overwrite in place. [2](#0-1) [3](#0-2) 

`set_member_balance` is called from:
- `enter_delegation_pool` (initial delegation)
- `add_to_delegation_pool` (balance increase)
- `exit_delegation_pool_intent` (partial/full exit intent)
- `enter_delegation_pool_from_staking_contract` (pool switch destination) [4](#0-3) [5](#0-4) 

Each distinct epoch in which the pool member changes their balance adds exactly one new entry. Over time, with no intermediate `claim_rewards` calls, the trace grows proportionally to the number of active epochs.

**`entry_to_claim_from` is only advanced on a successful claim:**

The `claim_rewards` function updates `pool_member_info.entry_to_claim_from` only after the loop completes successfully. If the transaction reverts due to out-of-gas, the pointer is never advanced, and every subsequent `claim_rewards` attempt must re-process the same large trace. [6](#0-5) 

### Impact Explanation

Once the trace is large enough that `calculate_rewards` exceeds the Starknet per-transaction gas limit, every future call to `claim_rewards` for that pool member will revert. The pool member's accumulated unclaimed yield becomes permanently inaccessible — there is no partial-claim mechanism, no way to split the computation, and no admin escape hatch. This constitutes **permanent freezing of unclaimed yield** (High severity).

### Likelihood Explanation

Starknet epochs are short (on the order of hours). A pool member who actively manages their delegation — adding or partially exiting across many epochs — without regularly claiming rewards can accumulate hundreds to thousands of trace entries over months of protocol operation. This is a realistic scenario for active delegators. The protocol itself acknowledges the risk in the source comment, indicating the developers are aware but have not mitigated it.

### Recommendation

1. **Paginated claiming**: Add a `max_entries` parameter to `claim_rewards` so the loop processes at most N entries per call, advancing `entry_to_claim_from` and persisting partial progress even when the full range is not yet processed.
2. **Bounded trace**: Enforce a maximum number of unclaimed balance-change entries per pool member (e.g., require a claim before a new balance change is accepted if the trace exceeds a threshold).
3. **Checkpoint on balance change**: Automatically settle rewards up to the current epoch whenever `set_member_balance` is called, keeping the unclaimed window small.

### Proof of Concept

1. Pool member Alice enters a delegation pool at epoch 1.
2. Alice calls `add_to_delegation_pool` or `exit_delegation_pool_intent` once per epoch for N epochs (each in a distinct epoch), never calling `claim_rewards`. Each call appends one entry to `pool_member_epoch_balance`.
3. After N epochs, Alice calls `claim_rewards`. The `calculate_rewards` loop must iterate over all N entries, each iteration performing a storage read (`pool_member_trace.at(entry_to_claim_from)`) and a `find_sigma` call (up to 3 additional storage reads).
4. For sufficiently large N (determined by Starknet's per-transaction gas cap), the transaction runs out of gas and reverts.
5. All subsequent `claim_rewards` calls also revert. Alice's accumulated yield is permanently frozen. [7](#0-6) [2](#0-1)

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

**File:** src/pool/pool.cairo (L256-293)
```text
        fn exit_delegation_pool_intent(ref self: ContractState, amount: Amount) {
            // Asserts.
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let old_delegated_stake = self.get_last_member_balance(:pool_member);
            let total_amount = old_delegated_stake + pool_member_info.unpool_amount;
            assert!(amount <= total_amount, "{}", GenericError::AMOUNT_TOO_HIGH);

            // Notify the staking contract of the removal intent.
            let unpool_time = self.undelegate_from_staking_contract_intent(:pool_member, :amount);

            // Edit the pool member to reflect the removal intent, and write to storage.
            if amount.is_zero() {
                pool_member_info.unpool_time = Option::None;
            } else {
                pool_member_info.unpool_time = Option::Some(unpool_time);
            }
            pool_member_info.unpool_amount = amount;
            let new_delegated_stake = total_amount - amount;
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Update the pool member's balance checkpoint.
            self.set_member_balance(:pool_member, amount: new_delegated_stake);

            // Emit events.
            self
                .emit(
                    Events::PoolMemberExitIntent {
                        pool_member, exit_timestamp: unpool_time, amount,
                    },
                );
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake, new_delegated_stake,
                    },
                );
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
