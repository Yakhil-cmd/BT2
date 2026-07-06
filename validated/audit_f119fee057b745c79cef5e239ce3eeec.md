### Title
Unbounded Loop in `calculate_rewards` Enables Permanent Freezing of Delegator Unclaimed Yield - (`File: src/pool/pool.cairo`)

### Summary
The `calculate_rewards` internal function in the Pool contract contains an unbounded loop that iterates over all unprocessed entries in a delegator's `pool_member_epoch_balance` trace. Because the trace grows by one entry per epoch whenever a delegator modifies their balance, a delegator who makes frequent balance changes across many epochs without claiming rewards will eventually be unable to call `claim_rewards` due to out-of-gas, permanently freezing their unclaimed yield.

### Finding Description

The `calculate_rewards` function in `src/pool/pool.cairo` iterates over the entire `pool_member_epoch_balance` trace from `entry_to_claim_from` up to the current epoch, with no upper bound on the number of iterations: [1](#0-0) 

The developers themselves acknowledge this risk in a comment: [2](#0-1) 

The trace grows via `set_member_balance`, which calls `trace.insert` with key `current_epoch + K`: [3](#0-2) 

The `insert` function only appends a new checkpoint when the epoch key differs from the last entry, meaning at most one new entry is added per epoch: [4](#0-3) 

Every call to `add_to_delegation_pool` or `exit_delegation_pool_intent` in a new epoch appends a new entry: [5](#0-4) [6](#0-5) 

The `claim_rewards` function calls `calculate_rewards` and updates `entry_to_claim_from` only upon a successful return: [7](#0-6) 

If the loop exceeds the block gas limit, the transaction reverts and `entry_to_claim_from` is never advanced, making every future `claim_rewards` call revert as well — permanently freezing the delegator's accumulated yield.

The same unbounded `calculate_rewards` call is also triggered by the view function `pool_member_info_v1`: [8](#0-7) 

### Impact Explanation

A delegator who accumulates enough balance-change epochs without claiming rewards will have their `claim_rewards` call permanently revert due to out-of-gas. Because `entry_to_claim_from` is only updated on a successful claim, no future call can succeed either. This permanently freezes all unclaimed yield for that delegator — matching the **High: Permanent freezing of unclaimed yield** impact category.

### Likelihood Explanation

The trace grows at most one entry per epoch. A delegator who calls `add_to_delegation_pool` or `exit_delegation_pool_intent` once per epoch and never claims rewards will accumulate N entries after N epochs. Each loop iteration performs multiple storage reads (expensive on Starknet). Once the number of unprocessed entries is large enough to exceed the block gas limit, the freeze becomes permanent. This is realistic for long-term delegators who dollar-cost-average into the pool across many epochs without regularly claiming. Additionally, a delegator's `reward_address` (which they set themselves) is also authorized to call `add_to_delegation_pool`, meaning a misconfigured or malicious reward address could accelerate trace growth.

### Recommendation

1. **Bound the loop**: Introduce a maximum number of iterations per `claim_rewards` call (e.g., process at most `MAX_ENTRIES` per call and allow partial claims, advancing `entry_to_claim_from` incrementally).
2. **Alternatively, checkpoint on every claim**: Force a balance-trace consolidation whenever `claim_rewards` is called, so the trace never grows beyond a small constant number of unprocessed entries relative to the last claim.
3. **Enforce a maximum trace depth**: Reject `add_to_delegation_pool` / `exit_delegation_pool_intent` calls if the number of unprocessed trace entries exceeds a safe threshold, prompting the user to claim first.

### Proof of Concept

1. Delegator calls `enter_delegation_pool` to join a pool.
2. Each epoch, the delegator calls `add_to_delegation_pool` with a small amount (or `exit_delegation_pool_intent` followed by re-entry), adding one new entry to `pool_member_epoch_balance` per epoch.
3. The delegator never calls `claim_rewards`.
4. After N epochs (where N is large enough that the loop gas cost exceeds the block gas limit), the delegator calls `claim_rewards`.
5. The `calculate_rewards` loop iterates over all N entries, exhausts gas, and reverts.
6. Because `entry_to_claim_from` was never updated, every subsequent `claim_rewards` call also reverts — the delegator's yield is permanently frozen.

### Citations

**File:** src/pool/pool.cairo (L241-243)
```text
            // Update the pool member's balance checkpoint.
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
            let new_delegated_stake = old_delegated_stake + amount;
```

**File:** src/pool/pool.cairo (L277-278)
```text
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
