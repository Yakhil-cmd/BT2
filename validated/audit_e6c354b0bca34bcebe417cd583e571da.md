### Title
Unbounded Iteration in `calculate_rewards` Over Pool Member Balance Trace - (File: `src/pool/pool.cairo`)

### Summary
The `calculate_rewards` function in the Pool contract iterates over a pool member's `pool_member_epoch_balance` trace without any upper bound. The trace grows by one entry per epoch whenever a pool member changes their delegation balance. Because `entry_to_claim_from` is only advanced when `claim_rewards` is called, a pool member who repeatedly changes their balance without claiming rewards accumulates an arbitrarily large trace. When `claim_rewards` is eventually called, the loop must traverse every accumulated entry, creating unbounded gas consumption that can permanently freeze the pool member's unclaimed rewards.

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` contains an explicitly acknowledged unbounded loop:

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

The loop iterates over `pool_member_epoch_balance`, a `PoolMemberBalanceTrace` (a `Vec`-backed checkpoint structure) stored per pool member. [2](#0-1) 

The trace grows by one entry per epoch whenever any of the following is called:

- `enter_delegation_pool` → `set_member_balance` → `trace.insert(key: epoch+K, ...)`
- `add_to_delegation_pool` → `increase_member_balance` → `set_member_balance` → `trace.insert(...)`
- `exit_delegation_pool_intent` → `set_member_balance` → `trace.insert(...)` [3](#0-2) 

The `insert` function only appends a new checkpoint when the epoch key differs from the last entry, so at most one new entry is added per epoch per pool member. [4](#0-3) 

Critically, `entry_to_claim_from` — the cursor that prevents re-iterating already-processed entries — is stored in `pool_member_info` and is **only advanced inside `claim_rewards`**: [5](#0-4) 

There is **no cap** on the trace length. The contract imposes no `maxBalanceChanges` or equivalent guard anywhere in the balance-update path.

`calculate_rewards` is also called from the view function `pool_member_info_v1`, meaning even read-only queries on a bloated trace will consume unbounded gas: [6](#0-5) 

### Impact Explanation

If a pool member accumulates N unclaimed balance-change epochs, the next `claim_rewards` call must iterate N times through storage reads and `find_sigma` lookups. Once N is large enough to exhaust the transaction gas limit, `claim_rewards` reverts on every attempt. Because `entry_to_claim_from` is only advanced inside `claim_rewards`, there is no partial-claim mechanism to recover. The pool member's entire accumulated unclaimed STRK reward balance becomes permanently inaccessible — matching the **High: Permanent freezing of unclaimed yield** impact tier. The same gas exhaustion applies to `pool_member_info_v1`, blocking any view of the member's state.

### Likelihood Explanation

Each epoch contributes at most one new trace entry. A pool member must therefore go many epochs without claiming while repeatedly changing their balance. Realistic scenarios:

1. **Automated delegation contracts** (e.g., a DeFi vault that rebalances delegation every epoch) that do not call `claim_rewards` on a regular schedule.
2. **Reward-address griefing**: `add_to_delegation_pool` is callable by either the pool member *or* their `reward_address`. If a pool member sets their reward address to an address controlled by an adversary, that adversary can call `add_to_delegation_pool` with a minimal amount every epoch, growing the victim's trace without the victim's active participation. [7](#0-6) 

Likelihood is **medium** for automated contracts and **low-to-medium** for the reward-address griefing path.

### Recommendation

1. **Add a `max_balance_trace_length` cap** (analogous to `maxCollaterals` in the HiFi fix). Reject calls to `add_to_delegation_pool` and `exit_delegation_pool_intent` when `pool_member_epoch_balance.entry(pool_member).length() - entry_to_claim_from` exceeds the cap, forcing the member to call `claim_rewards` first.
2. Alternatively, support **partial reward claims** that advance `entry_to_claim_from` by a bounded number of steps per call, allowing recovery even from a bloated trace.

### Proof of Concept

1. Pool member `Alice` enters a delegation pool.
2. Each epoch, Alice (or her reward address) calls `add_to_delegation_pool` with a minimal amount. Each call appends one entry to `pool_member_epoch_balance` for Alice.
3. Alice never calls `claim_rewards`, so `entry_to_claim_from` stays at 0.
4. After `N` epochs, `pool_member_epoch_balance.length()` for Alice equals `N`.
5. Alice calls `claim_rewards`. The loop in `calculate_rewards` iterates `N` times, each iteration performing multiple storage reads via `pool_member_trace.at(...)` and `find_sigma(...)`.
6. For sufficiently large `N`, the transaction exceeds the Starknet gas limit and reverts.
7. Every subsequent `claim_rewards` attempt also reverts. Alice's accumulated STRK rewards are permanently frozen. [8](#0-7) [9](#0-8)

### Citations

**File:** src/pool/pool.cairo (L107-109)
```text
        /// Map pool member to their epoch-balance info.
        pool_member_epoch_balance: Map<ContractAddress, PoolMemberBalanceTrace>,
        /// Map version to class hash of the contract.
```

**File:** src/pool/pool.cairo (L221-243)
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
