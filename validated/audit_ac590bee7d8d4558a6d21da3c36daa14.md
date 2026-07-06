### Title
Unbounded Loop in `calculate_rewards` Enables Permanent Freezing of Pool Member Unclaimed Yield - (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` function in the `Pool` contract iterates over every entry in a pool member's `pool_member_epoch_balance` trace without any bound. A pool member who repeatedly changes their delegated balance across many epochs — without claiming rewards — will accumulate an unbounded number of trace entries. When `claim_rewards` is eventually called, the loop iterates over all unclaimed entries and can exhaust the Starknet transaction gas limit, permanently freezing the pool member's unclaimed yield.

---

### Finding Description

`calculate_rewards` in `src/pool/pool.cairo` contains an explicit developer acknowledgment of the issue:

```
// **Note**: The loop iterates over the balance changes in the pool member's balance
// trace. This loop is unbounded but unlikely to exceed gas limits.
while entry_to_claim_from < pool_member_trace_length {
``` [1](#0-0) 

The trace (`pool_member_epoch_balance`) is a `Vec`-backed append-only structure. A new checkpoint is appended every time `set_member_balance` is called with a key (`epoch + K`) that differs from the last stored key. [2](#0-1) 

`set_member_balance` is called (directly or via `increase_member_balance`) by:

- `enter_delegation_pool` — line 201
- `add_to_delegation_pool` — line 242
- `exit_delegation_pool_intent` — line 278 [3](#0-2) 

Because the key is always `current_epoch + K`, each call in a **different epoch** appends a new checkpoint. There is no cap on how many checkpoints a pool member can accumulate.

The `entry_to_claim_from` cursor in `pool_member_info` advances after each successful `claim_rewards` call, so the loop only covers entries since the last claim. However, if a pool member makes many balance changes across many epochs without claiming, the loop must process all of them in a single transaction. [4](#0-3) 

The same unbounded `calculate_rewards` call is also made inside the view function `pool_member_info_v1`, meaning even reading the pool member's state would fail. [5](#0-4) 

---

### Impact Explanation

If the loop in `calculate_rewards` exhausts the transaction gas limit, `claim_rewards` reverts. Because the `entry_to_claim_from` cursor is only updated on success, every subsequent call starts from the same position and also reverts. The pool member's accrued yield is permanently unclaimable — matching the **"Permanent freezing of unclaimed yield"** impact category (High).

---

### Likelihood Explanation

Each new trace entry requires a balance change in a distinct epoch. The minimum epoch separation is enforced by the `K`-delay and the `exit_wait_window` (defaulting to 1 week). Under default parameters, accumulating thousands of entries takes years of continuous activity. However:

- There is **no minimum delegation amount** beyond `amount > 0`, so each cycle costs only gas.
- The epoch duration is governance-configurable; shorter epochs accelerate entry accumulation.
- A long-lived, active delegator who never claims rewards can reach the gas limit organically without any malicious intent.

Likelihood is **low** under default parameters but non-negligible over the protocol's lifetime.

---

### Recommendation

1. **Enforce a maximum number of unclaimed trace entries before allowing further balance changes.** If `pool_member_trace_length - entry_to_claim_from` exceeds a safe threshold (e.g., 500), require the pool member to call `claim_rewards` first.
2. **Alternatively, introduce a paginated `claim_rewards` that accepts a `max_entries` parameter**, advancing `entry_to_claim_from` by at most that many steps per call and accumulating partial rewards.
3. **Set a minimum delegation amount** to increase the cost of rapid cycling.

---

### Proof of Concept

1. Pool member `A` enters a delegation pool with the minimum non-zero amount.
2. Each epoch, `A` calls `add_to_delegation_pool(amount: 1)` — appending one new checkpoint per epoch.
3. `A` never calls `claim_rewards`, so `entry_to_claim_from` stays at 0.
4. After `N` epochs, `pool_member_epoch_balance` for `A` has `N` entries.
5. `A` calls `claim_rewards`. `calculate_rewards` enters the `while` loop and iterates all `N` entries, each requiring storage reads into `pool_member_epoch_balance` and `cumulative_rewards_trace`.
6. For sufficiently large `N`, the transaction hits the Starknet gas limit and reverts.
7. Every subsequent `claim_rewards` call also reverts from the same starting index — yield is permanently frozen. [6](#0-5) [7](#0-6)

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
