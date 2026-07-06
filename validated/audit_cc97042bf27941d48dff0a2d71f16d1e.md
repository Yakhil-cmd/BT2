### Title
Unbounded `pool_member_epoch_balance` Trace Causes Permanent DoS on `claim_rewards` - (File: `src/pool/pool.cairo`)

### Summary

The `calculate_rewards` internal function in the delegation pool contract iterates over the `pool_member_epoch_balance` trace in an explicitly unbounded loop. A pool member can deliberately grow this trace without bound by repeatedly changing their balance across different epochs without claiming rewards. Once the trace is large enough, every call to `claim_rewards` will exceed the gas limit, permanently freezing the pool member's unclaimed yield.

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` contains the following loop:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch {
        break;
    }
    ...
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

The loop iterates from `entry_to_claim_from` (the index saved at the last `claim_rewards` call) up to the current epoch boundary. The `entry_to_claim_from` cursor is only advanced when `claim_rewards` is successfully called: [2](#0-1) 

The trace grows via `set_member_balance`, which appends a new checkpoint whenever a balance change occurs at a new epoch key: [3](#0-2) 

`set_member_balance` is called from `increase_member_balance` (used in `enter_delegation_pool`) and directly from `exit_delegation_pool_intent`: [4](#0-3) 

The `insert` function in the trace only deduplicates if the same epoch key is reused; otherwise it always appends a new checkpoint: [5](#0-4) 

There is no cap on the number of checkpoints a single pool member can accumulate.

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Once the trace is large enough that iterating from `entry_to_claim_from` to the current epoch exceeds the Starknet transaction gas limit, every invocation of `claim_rewards` for that pool member will revert. Because `entry_to_claim_from` is only advanced inside `claim_rewards`, and `claim_rewards` is the only way to advance it, the pool member's accrued rewards become permanently unclaimable. The pool member's reward address also cannot claim on their behalf, since `claim_rewards` accepts either the pool member or the reward address as caller but executes the same unbounded loop. [6](#0-5) 

### Likelihood Explanation

**Medium.** The attack requires deliberate, repeated balance changes across many epochs without claiming. A concrete path:

1. Pool member enters the pool with amount `X`.
2. Each epoch: call `exit_delegation_pool_intent(amount: X/2)` → adds one trace entry; call `exit_delegation_pool_action` → withdraw; call `enter_delegation_pool(amount: X/2)` → adds another trace entry.
3. After `N` epochs without claiming, the unclaimed window of the trace contains `~2N` entries.
4. Once `N` is large enough, `claim_rewards` reverts on every call.

No privileged access is required; any pool member can execute this against themselves (self-griefing) or, if the reward address is a separate contract that depends on receiving rewards, against that address.

### Recommendation

1. **Add an upper bound** on the number of checkpoints a single pool member can accumulate in `pool_member_epoch_balance`. Enforce this cap inside `set_member_balance` or `increase_member_balance`.
2. **Alternatively**, implement a paginated `claim_rewards` that accepts a `max_entries` parameter, advances `entry_to_claim_from` by at most that many steps per call, and accumulates partial rewards across multiple transactions.
3. **Encourage frequent claiming** by documenting the risk and/or enforcing a maximum unclaimed window.

### Proof of Concept

```
Epoch 1:  pool_member calls enter_delegation_pool(amount: 1000)
          → trace: [(epoch=3, balance=1000)]  (K=2, so epoch+K=3)

Epoch 2:  pool_member calls exit_delegation_pool_intent(amount: 500)
          → trace: [(3, 1000), (4, 500)]
          pool_member calls exit_delegation_pool_action()
          pool_member calls enter_delegation_pool(amount: 500)
          → trace: [(3, 1000), (4, 500), (4, 1000)]  -- same key, deduplicated
          → trace: [(3, 1000), (4, 1000)]

Epoch 3:  pool_member calls exit_delegation_pool_intent(amount: 500)
          → trace: [(3,1000),(4,1000),(5,500)]
          pool_member calls exit_delegation_pool_action()
          pool_member calls enter_delegation_pool(amount: 500)
          → trace: [(3,1000),(4,1000),(5,1000)]

... repeat for N epochs without ever calling claim_rewards ...

Epoch N+2: pool_member calls claim_rewards()
           → calculate_rewards iterates from entry_to_claim_from=0 to N entries
           → if N is large enough, transaction runs out of gas → REVERT
           → entry_to_claim_from stays at 0
           → all subsequent claim_rewards calls also revert
           → pool member's yield is permanently frozen
``` [7](#0-6)

### Citations

**File:** src/pool/pool.cairo (L256-278)
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

**File:** src/pool/pool.cairo (L844-877)
```text
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
