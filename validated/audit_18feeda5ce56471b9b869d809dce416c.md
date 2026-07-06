### Title
Unbounded Loop in `calculate_rewards` Can Permanently Freeze Pool Member's Unclaimed Yield - (File: src/pool/pool.cairo)

### Summary
The `calculate_rewards` function in `pool.cairo` iterates over a pool member's entire `pool_member_epoch_balance` trace without any bound on the number of iterations. The code itself acknowledges this with the comment "This loop is unbounded but unlikely to exceed gas limits." A pool member who makes balance changes across many epochs without claiming rewards will accumulate an ever-growing trace, eventually causing `claim_rewards` to exceed Starknet's gas limit. Because there is no partial-claim mechanism and `entry_to_claim_from` is only committed on a successful call, the pool member's unclaimed yield becomes permanently frozen.

### Finding Description

**Root cause — `calculate_rewards` in `src/pool/pool.cairo` lines 857-877:**

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
```

The loop iterates from `entry_to_claim_from` (the index saved from the last successful `claim_rewards`) up to `pool_member_trace_length`. Each iteration performs at least one storage read (`pool_member_trace.at(...)`) and calls `find_sigma`, which itself reads from `cumulative_rewards_trace`. Both are storage-heavy operations.

**How the trace grows:**
The `pool_member_epoch_balance` trace is a `Vec`-backed structure. The `insert` function in `PoolMemberBalanceTrace` appends a new checkpoint whenever a balance change occurs in a new epoch (same-epoch changes overwrite the last entry). Every call to `add_to_delegation_pool`, `enter_delegation_pool`, or any path that calls `set_member_balance` / `increase_member_balance` in a new epoch appends one entry.

**Why there is no recovery:**
`entry_to_claim_from` is stored in `InternalPoolMemberInfoV1` and is only updated when `claim_rewards` completes successfully. If the transaction reverts due to gas exhaustion, the pointer is not advanced. There is no mechanism to claim rewards in batches or to advance the pointer independently. The pool member is permanently locked out of their yield.

**Call path (unprivileged pool member):**
1. Pool member calls `add_to_delegation_pool` (or `enter_delegation_pool`) once per epoch over N epochs without calling `claim_rewards`.
2. Each epoch appends one entry to `pool_member_epoch_balance`.
3. Pool member eventually calls `claim_rewards` → `calculate_rewards` → loop over N entries → gas exhaustion → revert.
4. `entry_to_claim_from` remains at its old value; the pool member can never advance past this point.

### Impact Explanation

**Permanent freezing of unclaimed yield (High).**
Once the trace is large enough that a single `claim_rewards` call exceeds the Starknet execution gas limit, the pool member's accumulated STRK rewards are permanently inaccessible. The principal (staked tokens) is unaffected, but all accrued yield is frozen forever. This matches the allowed High impact: *"Permanent freezing of unclaimed yield."*

A secondary impact is **unbounded gas consumption (Medium)** on every `pool_member_info_v1` view call, which also invokes `calculate_rewards` unconditionally.

### Likelihood Explanation

**Medium.** Starknet epochs are short (on the order of hours). A pool member who actively adjusts their delegation (e.g., topping up each epoch) and defers claiming for months will accumulate hundreds of trace entries. Each loop iteration performs multiple storage reads; at a few hundred iterations the gas cost becomes significant, and at a few thousand it will exceed the block gas limit. The code's own comment acknowledges the loop is unbounded, confirming the developers are aware of the risk but have not enforced a limit. No privileged access is required — any pool member can reach this state through normal protocol usage.

### Recommendation

1. **Enforce a per-call iteration cap** in `calculate_rewards` and return a partial result, storing the updated `entry_to_claim_from` so subsequent calls continue from where the previous one stopped. This is the direct analog of the Tezos fix (MR 15358) referenced in the original report.
2. Alternatively, expose a `claim_rewards_partial(max_entries: u64)` entry point that advances `entry_to_claim_from` by at most `max_entries` per call, allowing users to drain a large trace over multiple transactions.
3. Consider adding a protocol-level cap on how many balance-trace entries can accumulate before a claim is required (e.g., revert `add_to_delegation_pool` if `entry_to_claim_from` is more than `MAX_UNCLAIMED_EPOCHS` behind the current epoch).

### Proof of Concept

```
Epoch 1:  pool_member calls enter_delegation_pool(amount=X)
           → pool_member_epoch_balance[0] = {epoch: 1+K, balance: X}
Epoch 2:  pool_member calls add_to_delegation_pool(amount=1)
           → pool_member_epoch_balance[1] = {epoch: 2+K, balance: X+1}
...
Epoch N:  pool_member calls add_to_delegation_pool(amount=1)
           → pool_member_epoch_balance[N-1] = {epoch: N+K, balance: X+N-1}

pool_member calls claim_rewards(pool_member):
  → calculate_rewards iterates from entry_to_claim_from=0 to N-1
  → each iteration: pool_member_trace.at(i) [storage read]
                    + find_sigma(...) [storage read on cumulative_rewards_trace]
                    + compute_rewards_rounded_down(...)
  → at large N, transaction exceeds gas limit → REVERT
  → entry_to_claim_from remains 0
  → all subsequent claim_rewards calls also revert
  → pool member's yield is permanently frozen
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** src/pool/pool_member_balance_trace/trace.cairo (L150-175)
```text
    /// Inserts a (`key`, `value`) pair into a Trace so that it is stored as the checkpoint.
    /// This is done by either inserting a new checkpoint, or updating the last one.
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

**File:** src/pool/objects.cairo (L64-71)
```text
    /// The index of the first entry in the member balance trace for which:
    ///   `epoch >= reward_checkpoint.epoch`,
    /// (where `epoch = pool_member_epoch_balance[entry_to_claim_from]`),
    /// or the length of the trace if none exists.
    pub(crate) entry_to_claim_from: VecIndex,
    /// The checkpoint to start claiming rewards from.
    /// In particular, rewards for `reward_checkpoint.epoch` were not paid yet.
    pub(crate) reward_checkpoint: PoolMemberCheckpoint,
```
