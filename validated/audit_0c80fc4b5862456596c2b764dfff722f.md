### Title
Unbounded loop in `calculate_rewards` can permanently freeze pool member's unclaimed yield — (File: src/pool/pool.cairo)

---

### Summary

The `calculate_rewards` function in `pool.cairo` contains an unbounded `while` loop that iterates over every balance-change entry in a pool member's `pool_member_epoch_balance` trace. A pool member who accumulates many balance changes across epochs without claiming rewards can grow this trace large enough that a subsequent `claim_rewards` call exhausts the Starknet gas limit, permanently freezing their unclaimed yield. The code itself acknowledges the risk with an inline comment.

---

### Finding Description

`calculate_rewards` is called by `claim_rewards` and `pool_member_info_v1`. Its core loop is:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    ...
    let to_sigma = self.find_sigma(pool_member_checkpoint, curr_epoch: until_epoch);
    ...
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

Each iteration performs at minimum two storage reads: `pool_member_trace.at(entry_to_claim_from)` and `self.find_sigma(...)` (which itself reads from `cumulative_rewards_trace`). Storage reads are the most expensive operations on Starknet.

The trace (`pool_member_epoch_balance`) grows by one entry per epoch in which the member modifies their balance. The `insert` function only deduplicates when the key (epoch) is identical to the last entry; otherwise it appends a new checkpoint:

```cairo
} else {
    // Checkpoint keys must be non-decreasing.
    assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
``` [2](#0-1) 

The key used is `get_epoch_plus_k()`, which changes every epoch:

```cairo
fn set_member_balance(ref self: ContractState, pool_member: ContractAddress, amount: Amount) {
    let trace = self.pool_member_epoch_balance.entry(pool_member);
    ...
    trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance);
}
``` [3](#0-2) 

`set_member_balance` (and `increase_member_balance`) is called from `enter_delegation_pool`, `add_to_delegation_pool`, `exit_delegation_pool_intent`, and `enter_delegation_pool_from_staking_contract` — all publicly reachable by an unprivileged delegator. [4](#0-3) 

The `entry_to_claim_from` cursor is stored in `pool_member_info` and advanced only when `claim_rewards` is called. If a member makes one balance change per epoch for N epochs without claiming, the loop must traverse all N entries on the next `claim_rewards` call. [5](#0-4) 

---

### Impact Explanation

If the loop exceeds the Starknet transaction gas limit, `claim_rewards` reverts and the pool member's accumulated unclaimed yield becomes permanently inaccessible. There is no alternative entry point to claim rewards in smaller batches. This matches the allowed impact: **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

Any long-term delegator who calls `add_to_delegation_pool` (e.g., dollar-cost averaging) or `exit_delegation_pool_intent` once per epoch without regularly calling `claim_rewards` will organically grow their trace. The number of epochs required to hit the gas limit depends on Starknet's per-transaction gas cap, but given that each iteration performs multiple storage reads, a trace of a few thousand entries is sufficient. Starknet epochs are short (roughly weekly), so a multi-year delegator who never claims is a realistic victim. A malicious actor can also deliberately self-inflate their trace to lock their own rewards as a griefing demonstration, or to trap a reward address they no longer control.

---

### Recommendation

1. **Paginated claiming**: Add a `max_entries: Option<VecIndex>` parameter to `claim_rewards` so callers can process the trace in bounded chunks across multiple transactions.
2. **Trace compaction**: After `claim_rewards` advances `entry_to_claim_from`, allow pruning of consumed entries so the live window stays small.
3. **Enforce a maximum trace depth**: Cap the number of pending (unclaimed) balance-change entries per member and revert `add_to_delegation_pool` / `exit_delegation_pool_intent` if the cap is exceeded, forcing the member to claim first.

---

### Proof of Concept

1. Pool member Alice calls `add_to_delegation_pool` with a minimal amount once per epoch for N epochs, never calling `claim_rewards`. Each call appends one entry to `pool_member_epoch_balance` because `get_epoch_plus_k()` returns a new key each epoch.
2. After N epochs, `pool_member_epoch_balance` for Alice has N entries and `entry_to_claim_from == 0`.
3. Alice (or her reward address) calls `claim_rewards`.
4. `claim_rewards` calls `calculate_rewards`, which enters the `while` loop and iterates N times, each time executing `pool_member_trace.at(...)` and `find_sigma(...)` — both storage reads.
5. For sufficiently large N, the transaction exceeds the Starknet gas limit and reverts.
6. Alice's accumulated unclaimed rewards are permanently frozen; no alternative claim path exists. [6](#0-5) [7](#0-6)

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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L169-173)
```text
        } else {
            // Checkpoint keys must be non-decreasing.
            assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
            checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
        }
```
