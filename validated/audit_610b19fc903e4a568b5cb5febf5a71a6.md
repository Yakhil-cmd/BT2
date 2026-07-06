### Title
Pool Rewards Permanently Locked When Pool Balance Is Below `min_delegation_for_rewards` — (File: `src/pool/pool.cairo`)

---

### Summary

When a delegation pool's total balance is below `min_delegation_for_rewards`, the staking contract still transfers STRK reward tokens to the pool contract, but the pool's `cumulative_rewards_trace` receives a zero increment. These STRK tokens are permanently locked in the pool contract with no recovery path.

---

### Finding Description

**Root cause — two mismatched conditions in two contracts:**

**1. In `staking.cairo`, `calculate_staker_pools_rewards` (lines 1979–1999):**

`pool_rewards` is calculated proportionally to `pool_balance_curr_epoch / total_stake * total_rewards`. This value can be **non-zero** even when `pool_balance_curr_epoch` is below `min_delegation_for_rewards`. The entry is appended to `pool_rewards_array` whenever `pool_rewards.is_non_zero()`. [1](#0-0) 

**2. In `staking.cairo`, `update_pool_rewards` (lines 1872–1888):**

For every entry in `pool_rewards_array`, STRK tokens are unconditionally transferred to the pool contract via `send_rewards_to_delegation_pool`, and then `update_rewards_from_staking_contract` is called. [2](#0-1) 

**3. In `pool.cairo`, `update_rewards_from_staking_contract` (lines 569–587):**

This calls `compute_rewards_per_unit`, which returns **zero** when `total_stake < min_delegation_for_rewards`. The `cumulative_rewards_trace` is therefore updated with `last + 0`, i.e., no change. [3](#0-2) 

**4. In `pool.cairo`, `compute_rewards_per_unit` (lines 960–978):**

The developer comment explicitly acknowledges the mismatch: *"Delegation rewards lost when pool balance is less than `min_delegation_for_rewards`. The staking contract continues to forward `pool_rewards` to the pool contract even in this case."* [4](#0-3) 

**Result:** STRK tokens are transferred into the pool contract but the `cumulative_rewards_trace` is not updated. Since `claim_rewards` distributes rewards solely based on the cumulative trace, and there is no admin-withdrawal or sweep function in the pool contract, these tokens are permanently unrecoverable. [5](#0-4) 

---

### Impact Explanation

STRK reward tokens are permanently frozen inside the pool contract. No pool member can claim them (the trace was not updated), and no privileged role can recover them (no such function exists). This is a direct, permanent freeze of unclaimed yield.

Quantitatively: for a pool with 0.5 STRK delegated and a total network stake of 10,000 STRK earning 1 STRK/epoch, approximately `5 × 10¹³` FRI (~0.00005 STRK) is locked per epoch. Over thousands of epochs this accumulates irreversibly.

---

### Likelihood Explanation

The condition is reachable by any unprivileged delegator. The pool contract enforces only `amount.is_non_zero()` — there is no minimum delegation floor. [6](#0-5) 

A delegator who enters with any amount between `total_stake / total_rewards` (the integer-division floor for non-zero `pool_rewards`) and `min_delegation_for_rewards` (1 STRK = 10¹⁸ FRI for STRK pools; 1000 satoshis for 8-decimal BTC pools) will trigger the lock on every subsequent reward epoch. This range spans many orders of magnitude and is easily hit in practice for new or lightly-used pools.

---

### Recommendation

In `calculate_staker_pools_rewards` (`staking.cairo`), skip any pool whose `pool_balance_curr_epoch` (converted to native decimals) is below the pool's `min_delegation_for_rewards` before appending to `pool_rewards_array`. This prevents STRK tokens from being forwarded to a pool that cannot account for them.

Alternatively, guard the transfer inside `update_pool_rewards` with the same check before calling `send_rewards_to_delegation_pool`. [7](#0-6) 

---

### Proof of Concept

1. Staker stakes with pool enabled (own balance ≥ `min_stake`).
2. Delegator calls `enter_delegation_pool` with `amount = 5 × 10¹⁷` FRI (0.5 STRK, below `min_delegation_for_rewards = 10¹⁸`).
3. After K epochs, `update_rewards_from_attestation_contract` (or `update_rewards`) is called.
4. `calculate_staker_pools_rewards` computes `pool_rewards = epoch_rewards × (5×10¹⁷) / total_stake > 0` and appends the entry.
5. `update_pool_rewards` transfers `pool_rewards` STRK to the pool contract.
6. `update_rewards_from_staking_contract` is called with `pool_balance = 5×10¹⁷ < 10¹⁸`.
7. `compute_rewards_per_unit` returns 0; `cumulative_rewards_trace` is unchanged.
8. Delegator calls `claim_rewards` → receives 0 STRK.
9. The transferred STRK tokens remain in the pool contract with no recovery path, permanently locked.

### Citations

**File:** src/staking/staking.cairo (L1872-1888)
```text
            for (pool_contract, token_address, pool_balance, pool_rewards) in pools_rewards_data {
                let pool_dispatcher = IPoolDispatcher { contract_address: pool_contract };
                // Rewards are always in STRK.
                self
                    .send_rewards_to_delegation_pool(
                        :staker_address,
                        pool_address: pool_contract,
                        amount: pool_rewards,
                        token_dispatcher: strk_token_dispatcher,
                    );
                let decimals = self.get_token_decimals(:token_address);
                pool_dispatcher
                    .update_rewards_from_staking_contract(
                        rewards: pool_rewards,
                        pool_balance: pool_balance.to_native_amount(:decimals),
                    );
                pool_rewards_list.append((pool_contract, pool_rewards));
```

**File:** src/staking/staking.cairo (L1979-1999)
```text
                let pool_rewards_including_commission = if total_stake.is_non_zero() {
                    mul_wide_and_div(
                        lhs: total_rewards,
                        rhs: pool_balance_curr_epoch.to_amount_18_decimals(),
                        div: total_stake.to_amount_18_decimals(),
                    )
                        .expect_with_err(err: InternalError::REWARDS_COMPUTATION_OVERFLOW)
                } else {
                    Zero::zero()
                };
                let (commission_rewards, pool_rewards) = split_rewards_with_commission(
                    rewards_including_commission: pool_rewards_including_commission, :commission,
                );
                total_commission_rewards += commission_rewards;
                total_pools_rewards += pool_rewards;
                if pool_rewards.is_non_zero() {
                    pool_rewards_array
                        .append(
                            (pool_contract, token_address, pool_balance_curr_epoch, pool_rewards),
                        );
                }
```

**File:** src/pool/pool.cairo (L191-191)
```text
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
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

**File:** src/pool/pool.cairo (L960-978)
```text
        /// Compute the rewards for the pool trace.
        ///
        /// `staking_rewards` is in `STRK_DECIMALS` decimals.
        /// `total_stake` is in the contract's token decimals.
        /// **Note**: Delegation rewards lost when pool balance is less than
        /// `min_delegation_for_rewards`. The staking contract continues to forward
        /// `pool_rewards` to the pool contract even in this case.
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
