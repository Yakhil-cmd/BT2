### Title
Unbounded Loop in `Pool::calculate_rewards` Causes Permanent DoS on `claim_rewards` — (`src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` internal function in `pool.cairo` contains an unbounded loop that iterates over every balance-change checkpoint in a pool member's `pool_member_epoch_balance` trace. A delegator who repeatedly calls `add_to_delegation_pool` or `exit_delegation_pool_intent` across many different epochs without claiming rewards will accumulate an unbounded number of checkpoints. When `claim_rewards` (or `pool_member_info_v1`) is eventually called, the loop iterates over all of them, consuming gas proportional to the number of checkpoints. If the checkpoint count is large enough, the transaction will exceed the Starknet block gas limit, permanently freezing the delegator's unclaimed yield.

---

### Finding Description

In `src/pool/pool.cairo`, the `calculate_rewards` function (called by both `claim_rewards` and `pool_member_info_v1`) contains the following loop, which the code itself flags as unbounded:

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

Each iteration performs at least one storage read (`pool_member_trace.at(entry_to_claim_from)`) and calls `find_sigma`, which performs additional storage reads into `cumulative_rewards_trace`. The loop bound is `pool_member_trace_length`, which is the length of the `pool_member_epoch_balance` trace for the given pool member. [2](#0-1) 

New checkpoints are appended to this trace by `set_member_balance`, which is called by both `add_to_delegation_pool` and `exit_delegation_pool_intent`. The `insert` function in the trace only updates the last entry if the epoch key is identical; otherwise it appends a new checkpoint:

```cairo
if last.key == key {
    last.value = value;
    checkpoints[len - 1].write(last);
} else {
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value });
}
``` [3](#0-2) 

The key used is `get_epoch_plus_k()` (current epoch + K). Therefore, every call to `add_to_delegation_pool` or `exit_delegation_pool_intent` in a new epoch appends a distinct checkpoint. [4](#0-3) 

The `entry_to_claim_from` cursor is only persisted to storage if the `claim_rewards` transaction succeeds. If the transaction runs out of gas mid-loop, no state is written and the delegator's position is unchanged, making every subsequent attempt equally expensive and equally likely to fail. [5](#0-4) 

---

### Impact Explanation

A delegator who makes N balance changes across N distinct epochs without claiming rewards accumulates N checkpoints. A single `claim_rewards` call must iterate all N checkpoints. For a sufficiently large N, the gas cost exceeds the Starknet block gas limit. Because the cursor is not checkpointed on failure, the delegator can never claim their rewards — their unclaimed yield is permanently frozen.

This matches the allowed impact: **Permanent freezing of unclaimed yield** (High).

---

### Likelihood Explanation

The protocol is designed for long-term staking. A delegator who actively manages their position — adding to the pool or adjusting their exit intent across many epochs — will naturally accumulate many checkpoints. The code itself acknowledges the loop is unbounded with the comment "This loop is unbounded but unlikely to exceed gas limits," indicating the developers are aware of the risk but have not mitigated it. No minimum claim frequency is enforced, so a delegator can go arbitrarily many epochs between claims while continuing to change their balance.

---

### Recommendation

Add a `max_checkpoints` parameter to `claim_rewards` (and optionally `pool_member_info_v1`) that limits the number of balance-change entries processed per call. The `entry_to_claim_from` cursor is already stored in `pool_member_info`, so partial progress can be saved across multiple calls. This mirrors the fix applied to the analogous AI Arena vulnerability.

```cairo
fn claim_rewards(
    ref self: ContractState,
    pool_member: ContractAddress,
    max_checkpoints: Option<VecIndex>,  // None = process all
) -> Amount {
    // ...
    let limit = match max_checkpoints {
        Option::Some(n) => entry_to_claim_from + n,
        Option::None => pool_member_trace_length,
    };
    while entry_to_claim_from < limit && entry_to_claim_from < pool_member_trace_length {
        // ...
    }
}
```

---

### Proof of Concept

1. Delegator calls `enter_delegation_pool` at epoch E.
2. Delegator calls `add_to_delegation_pool` once per epoch for N epochs (advancing the epoch between each call), never calling `claim_rewards`.
3. Each call appends a new checkpoint to `pool_member_epoch_balance` because `get_epoch_plus_k()` differs each time.
4. After N epochs, delegator calls `claim_rewards`.
5. `calculate_rewards` iterates N times, each iteration performing multiple storage reads via `pool_member_trace.at(...)` and `find_sigma(...)`.
6. For large N (e.g., hundreds of epochs of active balance changes), the gas cost exceeds the block gas limit.
7. The transaction reverts, `entry_to_claim_from` is not updated, and every subsequent `claim_rewards` attempt fails identically — permanently freezing the delegator's accumulated yield. [6](#0-5) [7](#0-6)

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

**File:** src/pool/pool.cairo (L844-855)
```text
            let pool_member_trace = self.pool_member_epoch_balance.entry(pool_member);
            // Note: `until_epoch` is the current epoch.
            let until_epoch = until_checkpoint.epoch();

            let mut rewards = 0;

            let pool_member_trace_length = pool_member_trace.length();

            let mut from_sigma = self.find_sigma(from_checkpoint, curr_epoch: until_epoch);
            let mut from_balance = from_checkpoint.balance();

            let base_value = self.staking_rewards_base_value.read();
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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L163-174)
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
        (prev, value)
```
