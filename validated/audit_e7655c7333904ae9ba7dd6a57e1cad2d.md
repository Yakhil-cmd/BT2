### Title
Unbounded Loop in `calculate_rewards` Allows Pool Member to Permanently Freeze Their Own Unclaimed Yield - (File: src/pool/pool.cairo)

### Summary

The `calculate_rewards` function in `Pool` contains an explicitly acknowledged unbounded loop that iterates over every entry in a pool member's `pool_member_epoch_balance` trace. Because a pool member can inflate this trace cheaply by calling `exit_delegation_pool_intent(0)` once per epoch (no token transfer required), they can grow the trace to a size that causes `claim_rewards` to run out of gas on every invocation, permanently freezing their unclaimed yield.

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` iterates over the entire `pool_member_epoch_balance` trace from `entry_to_claim_from` to the current epoch:

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

The trace grows by one entry each time `set_member_balance` is called with a key (`epoch + K`) that differs from the last stored key:

```cairo
fn set_member_balance(ref self: ContractState, pool_member: ContractAddress, amount: Amount) {
    let trace = self.pool_member_epoch_balance.entry(pool_member);
    let pool_member_balance = PoolMemberBalanceTrait::new(
        balance: amount,
        cumulative_rewards_trace_idx: self.cumulative_rewards_trace_length() + 1,
    );
    trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance);
}
``` [2](#0-1) 

`set_member_balance` is called unconditionally at the end of `exit_delegation_pool_intent`, even when `amount == 0`:

```cairo
fn exit_delegation_pool_intent(ref self: ContractState, amount: Amount) {
    ...
    let new_delegated_stake = total_amount - amount;
    self.write_pool_member_info(:pool_member, :pool_member_info);
    // Update the pool member's balance checkpoint.
    self.set_member_balance(:pool_member, amount: new_delegated_stake);
``` [3](#0-2) 

The `insert` function in `PoolMemberBalanceTrace` appends a new checkpoint whenever the epoch key differs from the last stored key:

```cairo
} else {
    // Checkpoint keys must be non-decreasing.
    assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
``` [4](#0-3) 

**Attack path:**

1. Attacker enters the delegation pool with a minimal amount via `enter_delegation_pool`.
2. Each epoch, the attacker calls `exit_delegation_pool_intent(0)`. This passes the `amount <= total_amount` check (0 ≤ any balance), calls `remove_from_delegation_pool_intent` on the staking contract with amount=0 (a no-op when no prior intent exists), and then calls `set_member_balance` with the unchanged balance but a new epoch key — appending one new checkpoint to the trace. **No token transfer is required.**
3. After N epochs of this, the attacker's `pool_member_epoch_balance` trace has N entries.
4. When `claim_rewards` is called, `calculate_rewards` iterates over all N entries. Once N is large enough, the transaction runs out of gas and reverts.
5. Because `entry_to_claim_from` is only updated on a *successful* `claim_rewards` call, every subsequent attempt also OOGs. The unclaimed yield is permanently frozen. [5](#0-4) 

### Impact Explanation

The pool member's accumulated unclaimed rewards become permanently unclaimable. There is no mechanism to claim rewards in partial batches (the loop always starts from `entry_to_claim_from` and runs to the current epoch in a single call), so once the trace is large enough to cause OOG, the freeze is irreversible. This matches the allowed impact: **Permanent freezing of unclaimed yield (High)**.

### Likelihood Explanation

Any pool member can execute this attack against themselves at the cost of one gas-only transaction per epoch. Epoch advancement is driven by staker attestations (outside the attacker's direct control), but the attacker simply waits and submits one call per epoch. The minimum stake required to enter the pool is the only financial barrier. The developers themselves acknowledge the loop is unbounded in a code comment, confirming awareness of the risk.

### Recommendation

1. **Cap trace growth**: Enforce a maximum number of balance-change entries per pool member (e.g., reject `set_member_balance` if the trace already has an entry for the same `epoch + K` key and the balance is unchanged).
2. **Guard zero-amount intents**: Add `assert!(amount.is_non_zero(), ...)` at the top of `exit_delegation_pool_intent` to prevent free trace inflation via zero-amount calls.
3. **Paginated reward claiming**: Refactor `calculate_rewards` to accept a `max_iterations` parameter so rewards can be claimed in bounded batches, preventing permanent OOG lockout.

### Proof of Concept

```
Epoch 0: pool_member calls enter_delegation_pool(amount=MIN_STAKE)
         → trace length = 1

Epoch 1: pool_member calls exit_delegation_pool_intent(0)
         → set_member_balance called with key = epoch(1) + K
         → trace length = 2

Epoch 2: pool_member calls exit_delegation_pool_intent(0)
         → trace length = 3

...

Epoch N: pool_member calls exit_delegation_pool_intent(0)
         → trace length = N+1

Epoch N+1: pool_member (or reward_address) calls claim_rewards(pool_member)
           → calculate_rewards loops over entries 0..N
           → OOG revert
           → entry_to_claim_from unchanged (still 0)

Epoch N+2: claim_rewards called again → OOG again → permanent freeze
```

### Citations

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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L169-173)
```text
        } else {
            // Checkpoint keys must be non-decreasing.
            assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
            checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
        }
```
