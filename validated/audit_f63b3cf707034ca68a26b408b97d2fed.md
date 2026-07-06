Based on my research, I've found a valid analog to the M-19 gas manipulation vulnerability.

---

### Title
Unbounded Loop in `calculate_rewards` Enables Permanent Freezing of Pool Member Unclaimed Rewards — (`src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` function in `src/pool/pool.cairo` contains an explicitly acknowledged unbounded loop over a pool member's `pool_member_epoch_balance` trace. A pool member who repeatedly modifies their balance across many epochs without claiming rewards will grow this trace without bound. When `claim_rewards` is eventually called, the loop iterates over every accumulated entry, consuming gas proportional to the trace length. With a sufficiently large trace, the transaction will exceed Starknet's gas limit and revert, permanently freezing the pool member's unclaimed yield.

---

### Finding Description

The `calculate_rewards` internal function iterates over all balance-change checkpoints in `pool_member_epoch_balance` that fall between the last claimed checkpoint and the current epoch:

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

Each call to `set_member_balance` (invoked by both `add_to_delegation_pool` and `exit_delegation_pool_intent`) inserts a new checkpoint into the trace keyed by `current_epoch + K`:

```cairo
trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance);
``` [2](#0-1) 

The `insert` implementation only merges into the last entry when the key is identical; otherwise it appends a new entry:

```cairo
if last.key == key {
    last.value = value;
    checkpoints[len - 1].write(last);
} else {
    assert!(last.key < key, "{}", TraceErrors::UNORDERED_INSERTION);
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
``` [3](#0-2) 

Therefore, every balance modification made in a distinct epoch appends a new entry. A pool member who calls `add_to_delegation_pool` or `exit_delegation_pool_intent` across N different epochs without ever calling `claim_rewards` accumulates N entries. The `entry_to_claim_from` cursor stored in `pool_member_info` is only advanced by a successful `claim_rewards` call:

```cairo
pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
pool_member_info.reward_checkpoint = until_checkpoint;
``` [4](#0-3) 

If `claim_rewards` never succeeds (because it always runs out of gas), `entry_to_claim_from` is never advanced, so every subsequent attempt must re-iterate the entire trace from the beginning.

Inside the loop, each iteration calls `find_sigma`, which performs multiple storage reads from `cumulative_rewards_trace`: [5](#0-4) 

The combination of the unbounded outer loop and the per-iteration storage reads makes gas consumption grow linearly (or worse) with the trace length.

---

### Impact Explanation

Once the trace is large enough that `claim_rewards` exceeds the Starknet transaction gas limit, the pool member's accumulated rewards are **permanently frozen**: every future call to `claim_rewards` will revert for the same reason, and there is no partial-claim or pagination mechanism to break the work into smaller chunks. The pool member loses all unclaimed yield accrued since their last successful claim.

This matches the allowed impact: **Permanent freezing of unclaimed yield** (High) and **Unbounded gas consumption** (Medium).

---

### Likelihood Explanation

The attack is reachable by any unprivileged pool member (delegator). It does not require a privileged role, a compromised key, or any external dependency. A pool member who:

1. Regularly calls `add_to_delegation_pool` or `exit_delegation_pool_intent` across many epochs (e.g., monthly top-ups over years), and
2. Infrequently calls `claim_rewards`

will organically grow their trace to a size that triggers the gas limit. The protocol itself encourages long-term delegation, making this a realistic scenario. A malicious actor could also deliberately inflate their own trace to grief themselves (e.g., to demonstrate the vulnerability or to lock up rewards they no longer want to claim).

---

### Recommendation

1. **Paginate `claim_rewards`**: Accept an optional `max_entries` parameter so the loop processes at most N checkpoints per call, advancing `entry_to_claim_from` and accumulating partial rewards across multiple transactions.
2. **Cap trace growth**: Enforce a maximum number of pending (unclaimed) balance-change entries per pool member, reverting `add_to_delegation_pool` / `exit_delegation_pool_intent` if the cap is reached until the member claims rewards.
3. **Merge same-epoch entries eagerly**: The current `insert` already merges same-epoch entries; consider also merging entries that fall within the same reward-accounting window to reduce trace growth.

---

### Proof of Concept

1. Pool member Alice enters the delegation pool via `enter_delegation_pool`. This calls `set_member_balance`, inserting entry #1 at epoch `E + K`.
2. Alice calls `add_to_delegation_pool` once per epoch for 10,000 epochs without ever calling `claim_rewards`. Each call inserts a new entry into `pool_member_epoch_balance` (since the key `current_epoch + K` differs each epoch), growing the trace to 10,001 entries.
3. Alice (or anyone) calls `claim_rewards(alice)`. The `calculate_rewards` loop must iterate over all 10,001 entries, calling `find_sigma` (multiple storage reads) for each. The transaction exceeds Starknet's gas limit and reverts.
4. `entry_to_claim_from` in Alice's `pool_member_info` is never updated. Every future `claim_rewards` call starts from entry #0 and hits the same gas limit. Alice's rewards are permanently frozen. [6](#0-5) [7](#0-6)

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
