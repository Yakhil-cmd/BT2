### Title
Unbounded Loop in `calculate_rewards` Enables Permanent Freezing of Pool Member Rewards - (File: `src/pool/pool.cairo`)

### Summary
The `calculate_rewards` function in the delegation pool contract contains an explicitly acknowledged unbounded loop that iterates over every balance-change checkpoint in a pool member's `pool_member_epoch_balance` trace. An unprivileged pool member who makes balance changes across many epochs accumulates an unbounded number of checkpoints. Once the trace is large enough, `claim_rewards` exceeds the Starknet gas limit and permanently reverts, freezing all unclaimed yield for that member.

### Finding Description
Every call to `add_to_delegation_pool` or `exit_delegation_pool_intent` that occurs in a new epoch appends a new entry to the pool member's `pool_member_epoch_balance` trace via `set_member_balance` / `increase_member_balance`: [1](#0-0) 

The `insert` function only merges into the last checkpoint when the epoch key is identical; otherwise it appends a new checkpoint: [2](#0-1) 

When `claim_rewards` is called, it invokes `calculate_rewards`, which iterates over **every** entry in this trace with no upper bound: [3](#0-2) 

The developers themselves acknowledge the risk in a comment at line 858:

> `// **Note**: The loop iterates over the balance changes in the pool member's balance trace. This loop is unbounded but unlikely to exceed gas limits.`

Each loop iteration performs multiple storage reads (`pool_member_trace.at(entry_to_claim_from)` and `find_sigma`), which are among the most expensive operations on Starknet. A pool member who makes one balance change per epoch over a sufficient number of epochs will cause `claim_rewards` to exceed the block gas limit and revert permanently.

`claim_rewards` is the only path to transfer accrued rewards to the pool member: [4](#0-3) 

`exit_delegation_pool_action` does **not** call `calculate_rewards`, so the principal can still be withdrawn — but all accumulated yield is permanently frozen.

### Impact Explanation
Once the trace is large enough to exceed the gas limit, every call to `claim_rewards` reverts. The pool member's unclaimed STRK rewards are permanently locked in the pool contract with no recovery path. This matches the **High** impact category: *Permanent freezing of unclaimed yield*.

### Likelihood Explanation
Any pool member who actively manages their delegation — adding to the pool or partially exiting across many epochs — will grow their trace. One balance change per epoch is sufficient. Over a realistic protocol lifetime (hundreds or thousands of epochs), active delegators will naturally accumulate enough checkpoints to trigger this condition. No special privileges or external dependencies are required; the attacker is the victim of their own normal usage pattern.

### Recommendation
1. **Batch/paginate reward claims**: Introduce a `claim_rewards_partial(until_entry: VecIndex)` entrypoint that processes only a bounded slice of the trace per call, storing the updated `entry_to_claim_from` so subsequent calls continue from where the previous left off.
2. **Limit trace growth**: Consolidate checkpoints when consecutive entries fall within the same reward-accounting window, preventing unbounded accumulation.
3. **Add a hard cap**: Assert or enforce a maximum trace length per pool member and reject balance changes that would exceed it, surfacing the issue early rather than at claim time.

### Proof of Concept

```
1. Staker stakes and opens a delegation pool.
2. Pool member calls enter_delegation_pool(amount=X) at epoch E.
3. Pool member calls add_to_delegation_pool(amount=1) at epoch E+1.
   → set_member_balance inserts checkpoint at epoch E+1+K.
4. Pool member calls add_to_delegation_pool(amount=1) at epoch E+2.
   → set_member_balance inserts checkpoint at epoch E+2+K.
   (different key → new entry appended)
5. Repeat step 3-4 for N epochs (N ≈ several hundred to a few thousand,
   depending on Starknet's per-transaction gas cap and storage-read cost).
6. Pool member calls claim_rewards(pool_member).
   → calculate_rewards loops over all N checkpoints.
   → Each iteration reads pool_member_trace.at(i) and calls find_sigma
     (both are storage reads).
   → Transaction exceeds gas limit and reverts.
7. All subsequent claim_rewards calls also revert.
   Pool member's entire accumulated yield is permanently frozen.
``` [5](#0-4) [1](#0-0)

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
