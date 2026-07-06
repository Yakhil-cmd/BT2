### Title
Unbounded Loop in `calculate_rewards` Over Pool Member Balance Trace Enables Permanent Freezing of Unclaimed Yield - (File: src/pool/pool.cairo)

---

### Summary

The `calculate_rewards` function in `src/pool/pool.cairo` contains an explicitly acknowledged unbounded loop that iterates over a pool member's entire balance-change trace since their last claim. A delegator who makes many balance changes across many epochs without claiming rewards will grow this trace without bound. Once the trace is large enough, any call to `claim_rewards` will exceed Starknet's per-transaction gas limit, permanently freezing that delegator's unclaimed yield.

---

### Finding Description

`calculate_rewards` is called by `claim_rewards` and iterates over every entry in `pool_member_epoch_balance` that falls between the last-claimed checkpoint and the current epoch:

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

The trace (`PoolMemberBalanceTrace`) is a `Vec<PoolMemberBalanceCheckpoint>` that grows by one entry each time a balance change occurs in a **new** epoch. The `insert` function appends a new checkpoint only when the epoch key differs from the last entry:

```cairo
if last.key == key {
    last.value = value;          // update in-place
    checkpoints[len - 1].write(last);
} else {
    checkpoints.push(PoolMemberBalanceCheckpoint { key, value }); // new entry
}
``` [2](#0-1) 

Three public entry points append to this trace:

- `enter_delegation_pool` → `set_member_balance` (line 201)
- `add_to_delegation_pool` → `increase_member_balance` (line 242)
- `exit_delegation_pool_intent` → `set_member_balance` (line 278) [3](#0-2) [4](#0-3) [5](#0-4) 

The `entry_to_claim_from` cursor is persisted in `pool_member_info` and advanced after each successful `claim_rewards`, so the loop only covers entries since the last claim. However, if a delegator makes one balance change per epoch across N epochs without claiming, the loop must process N entries on the next claim call. [6](#0-5) 

---

### Impact Explanation

Once the trace between two consecutive claims grows large enough to exceed Starknet's per-transaction gas limit, `claim_rewards` will always revert for that pool member. Because `entry_to_claim_from` is only advanced inside a successful `claim_rewards` execution, there is no way to partially drain the trace. The delegator's accumulated yield is permanently frozen with no recovery path.

**Impact: High — Permanent freezing of unclaimed yield.**

---

### Likelihood Explanation

A delegator who actively manages their position (e.g., topping up or partially exiting once per epoch) and defers claiming rewards for an extended period will naturally accumulate a large trace. On Starknet, epochs are on the order of hours to days, so hundreds to thousands of entries can accumulate over months of normal usage. No malicious intent is required; the condition arises from ordinary long-term participation. The protocol itself acknowledges the loop is unbounded (the comment at line 858 says "unlikely to exceed gas limits"), confirming awareness of the risk without a mitigation.

---

### Recommendation

1. **Paginate `claim_rewards`**: Accept an optional `max_entries` parameter so the loop processes at most N entries per call, advancing `entry_to_claim_from` and accumulating partial rewards into `_unclaimed_rewards_from_v0` on each call.
2. **Enforce a maximum trace depth**: Cap the number of unclaimed balance-change entries per pool member (e.g., require claiming before a new balance change is accepted once the trace exceeds a threshold).
3. **Periodic forced checkpointing**: Automatically consolidate old trace entries into a single running-total checkpoint to bound the loop length.

---

### Proof of Concept

1. Staker creates a pool with `pool_enabled: true`.
2. Delegator calls `enter_delegation_pool` in epoch E₀ — trace length = 1.
3. For each subsequent epoch E₁ … E_N, delegator calls `add_to_delegation_pool` with a minimal amount (1 wei) — each call in a new epoch appends one entry; trace length grows to N+1.
4. Delegator never calls `claim_rewards` during this period.
5. After N epochs, delegator calls `claim_rewards`. `calculate_rewards` must loop over all N+1 entries.
6. For sufficiently large N (determined by Starknet's gas limit per transaction), the call reverts with out-of-gas, and all accumulated rewards are permanently frozen.

The attacker-controlled entry path is entirely unprivileged: `add_to_delegation_pool` requires only that the caller is the pool member or their reward address, with no rate limiting or trace-depth check. [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** src/pool/pool.cairo (L201-201)
```text
            self.set_member_balance(:pool_member, :amount);
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

**File:** src/pool/pool.cairo (L278-278)
```text
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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L12-14)
```text
pub struct PoolMemberBalanceTrace {
    checkpoints: Vec<PoolMemberBalanceCheckpoint>,
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
