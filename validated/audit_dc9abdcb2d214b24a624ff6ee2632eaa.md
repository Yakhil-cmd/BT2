### Title
Unbounded Loop in `calculate_rewards` Can Permanently Freeze Pool Member's Unclaimed Yield - (File: src/pool/pool.cairo)

### Summary
The `calculate_rewards` function in `Pool` contains an unbounded `while` loop that iterates over every balance checkpoint in a pool member's `pool_member_epoch_balance` trace since their last reward claim. Because `claim_rewards` provides no batching mechanism (no `max_iterations` parameter), a pool member who accumulates enough balance checkpoints across epochs without claiming rewards will eventually be unable to claim at all — their transaction will always run out of gas, permanently freezing their unclaimed yield.

### Finding Description
In `src/pool/pool.cairo`, the internal `calculate_rewards` function iterates over the pool member's balance trace from `entry_to_claim_from` up to the first checkpoint whose epoch is ≥ the current epoch:

```cairo
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
    let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
    if pool_member_checkpoint.epoch() >= until_epoch {
        break;
    }
    // ... reward accumulation ...
    entry_to_claim_from += 1;
}
``` [1](#0-0) 

The `entry_to_claim_from` cursor is stored in `pool_member_info` and is only advanced when `claim_rewards` is successfully called:

```cairo
pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
``` [2](#0-1) 

New checkpoints are appended to `pool_member_epoch_balance` by `set_member_balance`, which is called on every balance-changing operation (`enter_delegation_pool`, `add_to_delegation_pool`, `exit_delegation_pool_intent`, `enter_delegation_pool_from_staking_contract`). The trace's `insert` logic only merges entries with the same key (same epoch + K), so each distinct epoch in which the member changes their balance produces a new checkpoint: [3](#0-2) 

The `claim_rewards` entry point accepts only `pool_member: ContractAddress` — there is no `max_iterations`, `from_epoch`, or `to_epoch` parameter to allow partial/batched claiming: [4](#0-3) 

### Impact Explanation
If a pool member has made balance changes across N distinct epochs without ever calling `claim_rewards`, the loop must process N checkpoints in a single transaction. Once N is large enough to exhaust the Starknet transaction gas limit, every subsequent `claim_rewards` call will revert with OOG. Because `entry_to_claim_from` is only updated on a successful `claim_rewards`, the cursor never advances, and the member's accumulated yield is permanently frozen — it can never be transferred to the reward address.

This matches the allowed impact: **Permanent freezing of unclaimed yield** (High).

### Likelihood Explanation
Each epoch in which the pool member modifies their balance (deposit, partial exit, re-entry) adds one checkpoint. A member who is active across many epochs and defers claiming rewards — a common pattern for long-term delegators — will accumulate checkpoints linearly with time. The developers themselves acknowledge the risk in a code comment: *"This loop is unbounded but unlikely to exceed gas limits."* The likelihood is low-to-medium for typical users but becomes a certainty for any member who has been active for a sufficiently large number of epochs without claiming.

### Recommendation
1. Add a `max_iterations: u64` parameter to `claim_rewards` (and the underlying `calculate_rewards`) so callers can process checkpoints in bounded batches, similar to how Morpho's report recommends bounding `_defaultIterations`.
2. Alternatively, enforce a maximum number of unclaimed checkpoints per pool member (e.g., require claiming before a new checkpoint can be appended once a threshold is reached).
3. At minimum, document the safe upper bound for accumulated checkpoints and add an on-chain guard that reverts with a clear error rather than silently OOGing.

### Proof of Concept
1. Pool member Alice calls `enter_delegation_pool` in epoch 1 (checkpoint 1 created).
2. Alice calls `add_to_delegation_pool` once per epoch for epochs 2 through N, never calling `claim_rewards` (N−1 additional checkpoints created, one per epoch).
3. In epoch N+1, Alice calls `claim_rewards`. The `calculate_rewards` loop must iterate over all N checkpoints.
4. For sufficiently large N, the transaction runs out of gas and reverts.
5. Because `entry_to_claim_from` was never updated (the transaction reverted), every future `claim_rewards` call also reverts — Alice's yield is permanently frozen. [5](#0-4)

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
