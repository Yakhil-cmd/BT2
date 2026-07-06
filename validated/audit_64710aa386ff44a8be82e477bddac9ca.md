### Title
Pool Rewards Permanently Frozen When Delegated Balance Falls Below `min_delegation_for_rewards` — (File: `src/pool/pool.cairo`)

---

### Summary

When the total delegated stake in a pool falls below `min_delegation_for_rewards` (1 STRK = `10^18`), `compute_rewards_per_unit` silently returns `0`, leaving the pool's cumulative rewards trace unchanged. The staking contract, however, still transfers the full pool reward amount to the pool contract. Those tokens are permanently unclaimable by any pool member.

---

### Finding Description

In `pool.cairo`, `compute_rewards_per_unit` guards against overflow by returning `Zero::zero()` when `total_stake` is below the minimum: [1](#0-0) 

This function is called inside `update_rewards_from_staking_contract`, which the staking contract invokes **after** it has already transferred the reward tokens to the pool contract via `send_rewards_to_delegation_pool`: [2](#0-1) 

The developer comment inside `compute_rewards_per_unit` explicitly acknowledges the mismatch:

> **Note**: Delegation rewards lost when pool balance is less than `min_delegation_for_rewards`. The staking contract continues to forward `pool_rewards` to the pool contract even in this case. [3](#0-2) 

The staking-side transfer function that moves tokens into the pool before the trace update: [4](#0-3) 

Because `compute_rewards_per_unit` returns `0`, the `cumulative_rewards_trace` is incremented by `0`. Pool members' `calculate_rewards` therefore computes `0` rewards for those epochs, and the transferred tokens have no corresponding accounting entry — they are irrecoverable. The pool contract exposes no administrative withdrawal path.

The structural parallel to the external report is exact:

| External (NomadFacet) | This codebase (Pool) |
|---|---|
| Adopted asset converted to local | Staking contract transfers STRK rewards to pool |
| Aave `backUnbacked` fails → `amountIn = 0` | `pool_balance < min_for_rewards` → `compute_rewards_per_unit` returns `0` |
| Local asset distributed = 0; adopted asset stuck | Cumulative trace not updated; reward tokens stuck |

---

### Impact Explanation

STRK reward tokens transferred to the pool contract are permanently frozen — no pool member can ever claim them. This matches the allowed High impact: **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

The condition `pool_balance < 10^18` (< 1 STRK) is reachable by any unprivileged actor:

- A delegator calls `exit_delegation_pool_intent` with their full balance, reducing the pool's active stake below the threshold before the staker's next reward epoch.
- A newly opened pool that has not yet attracted meaningful delegation will sit below the threshold for multiple epochs.
- No privileged role is required; the entry path is the standard `exit_delegation_pool_intent` → wait → `exit_delegation_pool_action` flow. [5](#0-4) 

---

### Recommendation

Decouple the token transfer from the trace update: only call `send_rewards_to_delegation_pool` (and therefore transfer tokens) when `pool_balance >= min_delegation_for_rewards`. If the pool is below the threshold, either skip the transfer entirely for that epoch or accumulate the skipped rewards in a separate recoverable storage slot.

---

### Proof of Concept

1. Staker S opens a STRK delegation pool.
2. Pool member M delegates `0.5 STRK` (`5 × 10^17 < 10^18 = min_delegation_for_rewards`).
3. Consensus block reward triggers `update_rewards` → `_update_rewards` in the staking contract.
4. Staking contract computes pool rewards `R > 0` and calls `send_rewards_to_delegation_pool(pool, R)` — `R` STRK tokens land in the pool contract.
5. Staking contract calls `pool.update_rewards_from_staking_contract(rewards=R, pool_balance=0.5 STRK)`.
6. Inside the pool:

### Citations

**File:** src/pool/pool.cairo (L256-293)
```text
        fn exit_delegation_pool_intent(ref self: ContractState, amount: Amount) {
            // Asserts.
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let old_delegated_stake = self.get_last_member_balance(:pool_member);
            let total_amount = old_delegated_stake + pool_member_info.unpool_amount;
            assert!(amount <= total_amount, "{}", GenericError::AMOUNT_TOO_HIGH);

            // Notify the staking contract of the removal intent.
            let unpool_time = self.undelegate_from_staking_contract_intent(:pool_member, :amount);

            // Edit the pool member to reflect the removal intent, and write to storage.
            if amount.is_zero() {
                pool_member_info.unpool_time = Option::None;
            } else {
                pool_member_info.unpool_time = Option::Some(unpool_time);
            }
            pool_member_info.unpool_amount = amount;
            let new_delegated_stake = total_amount - amount;
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Update the pool member's balance checkpoint.
            self.set_member_balance(:pool_member, amount: new_delegated_stake);

            // Emit events.
            self
                .emit(
                    Events::PoolMemberExitIntent {
                        pool_member, exit_timestamp: unpool_time, amount,
                    },
                );
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake, new_delegated_stake,
                    },
                );
        }
```

**File:** src/pool/pool.cairo (L569-587)
```text
        fn update_rewards_from_staking_contract(
            ref self: ContractState, rewards: Amount, pool_balance: Amount,
        ) {
            self.assert_caller_is_staking_contract();

            // `rewards_info` is initialized in the constructor or in the upgrade proccess,
            // so unwrapping should be safe.
            let (_, last) = self.cumulative_rewards_trace.last().unwrap();
            self
                .cumulative_rewards_trace
                .insert(
                    key: self.get_current_epoch(),
                    value: last
                        + self
                            .compute_rewards_per_unit(
                                staking_rewards: rewards, total_stake: pool_balance,
                            ),
                );
        }
```

**File:** src/pool/pool.cairo (L960-966)
```text
        /// Compute the rewards for the pool trace.
        ///
        /// `staking_rewards` is in `STRK_DECIMALS` decimals.
        /// `total_stake` is in the contract's token decimals.
        /// **Note**: Delegation rewards lost when pool balance is less than
        /// `min_delegation_for_rewards`. The staking contract continues to forward
        /// `pool_rewards` to the pool contract even in this case.
```

**File:** src/pool/pool.cairo (L967-978)
```text
        fn compute_rewards_per_unit(
            self: @ContractState, staking_rewards: Amount, total_stake: Amount,
        ) -> Index {
            // Return zero if the total stake is too small, to avoid overflow below.
            if total_stake < self.min_delegation_for_rewards.read() {
                return Zero::zero();
            }
            mul_wide_and_div(
                lhs: staking_rewards, rhs: self.staking_rewards_base_value.read(), div: total_stake,
            )
                .expect_with_err(err: InternalError::REWARDS_COMPUTATION_OVERFLOW)
        }
```

**File:** src/staking/staking.cairo (L1635-1649)
```text
        fn send_rewards_to_delegation_pool(
            ref self: ContractState,
            staker_address: ContractAddress,
            pool_address: ContractAddress,
            amount: Amount,
            token_dispatcher: IERC20Dispatcher,
        ) {
            token_dispatcher.checked_transfer(recipient: pool_address, amount: amount.into());
            self
                .emit(
                    Events::RewardsSuppliedToDelegationPool {
                        staker_address, pool_address, amount,
                    },
                );
        }
```
