### Title
Unbounded `pool_member_epoch_balance` Trace Causes Permanent Freezing of Unclaimed Yield via Gas Exhaustion in `claim_rewards` - (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` function in `src/pool/pool.cairo` iterates over a pool member's entire `pool_member_epoch_balance` trace in a single unbounded loop. Because every balance-modifying action (`add_to_delegation_pool`, `exit_delegation_pool_intent`, `enter_delegation_pool`) appends a new checkpoint to this trace whenever it is called in a new epoch, a pool member who interacts once per epoch over a sufficient number of epochs will grow the trace until `claim_rewards` exceeds the Starknet per-transaction gas limit and permanently reverts, freezing all unclaimed yield.

---

### Finding Description

**Root cause — unbounded loop in `calculate_rewards`:**

The function explicitly acknowledges the risk:

```
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
``` [1](#0-0) 

The loop iterates from `entry_to_claim_from` to `pool_member_trace_length`, processing every balance-change checkpoint in a single transaction. There is no partial-progress mechanism within a single `claim_rewards` call — the entire range must complete atomically.

**How the trace grows:**

`set_member_balance` inserts a new checkpoint keyed by `current_epoch + K`:

```cairo
trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance);
``` [2](#0-1) 

The underlying `insert` implementation only deduplicates if the key is identical to the last entry; otherwise it appends a new checkpoint:

```cairo
if last.key == key {
    last.value = value;
    checkpoints[len - 1].write(last);
} else {
    assert!(last.key < key, ...);
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
``` [3](#0-2) 

Therefore, one call to any of the following per epoch appends one new entry:
- `add_to_delegation_pool` → `increase_member_balance` → `set_member_balance` [4](#0-3) 
- `exit_delegation_pool_intent` → `set_member_balance` [5](#0-4) 
- `enter_delegation_pool` → `set_member_balance` [6](#0-5) 

**Why `entry_to_claim_from` does not mitigate this:**

`claim_rewards` does save the updated `entry_to_claim_from` after a successful call:

```cairo
pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
pool_member_info.reward_checkpoint = until_checkpoint;
self.write_pool_member_info(:pool_member, :pool_member_info);
``` [7](#0-6) 

However, this only helps if the user claims frequently. If a pool member accumulates N balance changes across N epochs without claiming, the next `claim_rewards` call must iterate over all N entries in one transaction. Once N is large enough to exceed the block gas limit, every future `claim_rewards` call reverts, and the rewards are permanently frozen.

**Attack path:**

1. Attacker (pool member) enters a delegation pool via `enter_delegation_pool`.
2. Each epoch, the attacker calls `add_to_delegation_pool` with the minimum non-zero amount (1 token unit). This appends one new entry to `pool_member_epoch_balance`.
3. The attacker never calls `claim_rewards`, allowing the trace to grow.
4. After sufficiently many epochs (the exact threshold depends on Starknet's per-transaction gas cap), `claim_rewards` reverts on every attempt due to gas exhaustion.
5. The pool member's accumulated yield is permanently frozen.

The attacker only needs to be a normal pool member — no privileged access is required. The minimum cost per epoch is one `add_to_delegation_pool` transaction with 1 token unit.

---

### Impact Explanation

**Permanent freezing of unclaimed yield (High).**

Once the trace exceeds the gas limit threshold, `claim_rewards` will always revert. There is no administrative escape hatch, no partial-claim mechanism, and no way to prune the trace. The pool member's entire accumulated unclaimed reward balance becomes permanently inaccessible. This matches the allowed High impact: *"Permanent freezing of unclaimed yield or unclaimed royalties."*

The same loop is also invoked by the read-only `pool_member_info_v1` view function:

```cairo
let (rewards, _) = self.calculate_rewards(
    :pool_member,
    from_checkpoint: pool_member_info.reward_checkpoint,
    until_checkpoint: self.get_current_checkpoint(:pool_member),
    entry_to_claim_from: pool_member_info.entry_to_claim_from,
);
``` [8](#0-7) 

This means even querying the pool member's state becomes impossible once the trace is large enough.

---

### Likelihood Explanation

**Medium.** The attack requires one transaction per epoch over many epochs. Starknet epochs are short (on the order of hours), so a determined attacker can grow the trace to a dangerous size within weeks to months. The cost is low: only the minimum delegation amount and gas fees per epoch. The condition can also arise organically for a long-lived, active pool member who simply forgets to claim rewards regularly. The code itself acknowledges the risk with the comment "unlikely to exceed gas limits," which is not a guarantee.

---

### Recommendation

1. **Add a partial-claim mechanism**: Allow `claim_rewards` to accept a `max_entries` parameter, processing only a bounded number of trace entries per call and saving progress. The `entry_to_claim_from` field already exists for this purpose — it just needs to be usable mid-range.
2. **Enforce a maximum trace length**: Cap the number of entries in `pool_member_epoch_balance` per pool member (e.g., by requiring `claim_rewards` before further balance changes are allowed once the trace exceeds a threshold).
3. **Compact the trace on claim**: After a successful `claim_rewards`, truncate all processed entries from the trace so the next call starts from a clean state.

---

### Proof of Concept

```
Epoch 1:  pool_member calls enter_delegation_pool(amount=MIN)
          → trace length = 1

Epoch 2:  pool_member calls add_to_delegation_pool(amount=1)
          → trace length = 2

Epoch 3:  pool_member calls add_to_delegation_pool(amount=1)
          → trace length = 3

...

Epoch N:  pool_member calls add_to_delegation_pool(amount=1)
          → trace length = N

Epoch N+1: pool_member calls claim_rewards(pool_member)
           → calculate_rewards loops N times
           → if N > gas_limit_threshold: REVERT (out of gas)
           → all accumulated rewards permanently frozen
```

The `insert` function confirms each distinct epoch produces a new checkpoint (no deduplication across epochs), and `calculate_rewards` confirms the loop has no early-exit or gas-check mechanism. [1](#0-0) [9](#0-8)

### Citations

**File:** src/pool/pool.cairo (L182-219)
```text
        fn enter_delegation_pool(
            ref self: ContractState, reward_address: ContractAddress, amount: Amount,
        ) {
            // Asserts.
            self.assert_staker_is_active();
            let pool_member = get_caller_address();
            assert!(
                self.pool_member_info.read(pool_member).is_none(), "{}", Error::POOL_MEMBER_EXISTS,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let token_dispatcher = self.token_dispatcher.read();
            let token_address = token_dispatcher.contract_address;
            assert!(token_address != pool_member, "{}", Error::POOL_MEMBER_IS_TOKEN);
            assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
            // Transfer funds from the delegator to the staking contract.
            let staker_address = self.staker_address.read();
            transfer_from_delegator(:pool_member, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);

            self.set_member_balance(:pool_member, :amount);

            // Create the pool member record.
            self
                .pool_member_info
                .write(pool_member, VInternalPoolMemberInfoTrait::new_latest(:reward_address));

            // Emit events.
            self
                .emit(
                    Events::NewPoolMember { pool_member, staker_address, reward_address, amount },
                );
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake: Zero::zero(), new_delegated_stake: amount,
                    },
                );
        }
```

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

**File:** src/pool/pool.cairo (L358-362)
```text
            pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
            pool_member_info.reward_checkpoint = until_checkpoint;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);
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

**File:** src/pool/pool.cairo (L721-729)
```text
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
