### Title
STRK Rewards Permanently Stuck in Pool Contract When BTC Pool Balance Falls Below `min_delegation_for_rewards` — (File: src/pool/pool.cairo)

---

### Summary
When a BTC delegation pool's total native balance is below `min_delegation_for_rewards`, the staking contract still computes non-zero `pool_rewards` (using 18-decimal normalized amounts) and transfers STRK to the pool contract. However, the pool contract's `compute_rewards_per_unit` returns zero for the same epoch, leaving the cumulative sigma unchanged. Delegators can never claim the transferred STRK, which is permanently frozen in the pool contract.

---

### Finding Description

**Step 1 — Reward calculation in staking contract uses normalized (18-decimal) amounts.**

In `calculate_staker_pools_rewards`, the pool balance is normalized to 18 decimals before computing rewards:

```cairo
let pool_balance_curr_epoch = self.get_staker_delegated_balance_at_epoch(...);
let pool_rewards_including_commission = mul_wide_and_div(
    lhs: total_rewards,
    rhs: pool_balance_curr_epoch.to_amount_18_decimals(),
    div: total_stake.to_amount_18_decimals(),
)
``` [1](#0-0) 

If `pool_rewards > 0`, the pool is added to `pool_rewards_array` and STRK is transferred to the pool contract:

```cairo
if pool_rewards.is_non_zero() {
    pool_rewards_array.append((pool_contract, token_address, pool_balance_curr_epoch, pool_rewards));
}
``` [2](#0-1) 

**Step 2 — STRK is sent to the pool contract unconditionally for all non-zero-reward pools.** [3](#0-2) 

The `pool_balance` passed to `update_rewards_from_staking_contract` is converted back to native token decimals:
```cairo
pool_balance: pool_balance.to_native_amount(:decimals)
```

**Step 3 — Pool contract's `compute_rewards_per_unit` returns zero when native balance < `min_delegation_for_rewards`.**

```cairo
fn compute_rewards_per_unit(self: @ContractState, staking_rewards: Amount, total_stake: Amount) -> Index {
    if total_stake < self.min_delegation_for_rewards.read() {
        return Zero::zero();
    }
    ...
}
``` [4](#0-3) 

The `min_delegation_for_rewards` for BTC (8 decimals) is `10^(8-5) = 1000` satoshis: [5](#0-4) 

**Step 4 — The cumulative sigma is not updated, so delegators can never claim the STRK.**

```cairo
self.cumulative_rewards_trace.insert(
    key: self.get_current_epoch(),
    value: last + self.compute_rewards_per_unit(staking_rewards: rewards, total_stake: pool_balance),
);
``` [6](#0-5) 

When `compute_rewards_per_unit` returns 0, `last + 0 = last` — the sigma is unchanged. The STRK already transferred to the pool contract is permanently unclaimable.

The code itself documents this behavior:
> **Note**: Delegation rewards lost when pool balance is less than `min_delegation_for_rewards`. The staking contract continues to forward `pool_rewards` to the pool contract even in this case. [7](#0-6) 

**Step 5 — No minimum delegation check in `enter_delegation_pool`.**

The pool only checks `amount.is_non_zero()`: [8](#0-7) 

Any delegator can enter a BTC pool with 1 satoshi, keeping the total pool balance below `min_delegation_for_rewards`.

---

### Impact Explanation

STRK rewards are transferred from the reward supplier to the pool contract but the cumulative sigma is never incremented for those epochs. Since `claim_rewards` computes `amount * (sigma_until - sigma_from) / base_value`, and the sigma delta is zero, delegators receive zero. There is no sweep or recovery function in the pool contract. The STRK is permanently frozen.

**Impact**: Permanent freezing of unclaimed yield (High).

---

### Likelihood Explanation

- `enter_delegation_pool` has no minimum amount check beyond `amount.is_non_zero()`.
- For BTC-8 decimals, the threshold is only 1000 satoshis (~$0.001 at current prices). Any delegator entering with fewer than 1000 satoshis triggers this.
- The condition persists as long as the total pool balance stays below the threshold. A single small delegator in an otherwise empty pool is sufficient.
- The staking contract's `calculate_staker_pools_rewards` uses normalized 18-decimal amounts, so even 1 satoshi produces non-zero `pool_rewards`, causing STRK to be forwarded.

---

### Recommendation

1. **Enforce a minimum delegation amount** in `enter_delegation_pool` equal to `min_delegation_for_rewards` for the pool's token, preventing pool balances from falling below the threshold.
2. **Alternatively**, in `update_pool_rewards` (staking contract), skip sending STRK and calling `update_rewards_from_staking_contract` when `pool_balance.to_native_amount(decimals) < min_delegation_for_rewards`. This requires the staking contract to know the pool's threshold, or the pool to return a boolean from `update_rewards_from_staking_contract` indicating whether the sigma was updated.
3. **At minimum**, add a recovery mechanism in the pool contract to allow governance to sweep stuck STRK.

---

### Proof of Concept

1. Deploy a BTC-8 pool (staker calls `set_open_for_delegation` with a BTC token address having 8 decimals).
2. Delegator calls `enter_delegation_pool(reward_address, amount: 500)` — 500 satoshis, below `min_delegation_for_rewards = 1000`.
3. Advance K epochs so the balance becomes effective.
4. Staker attests; `update_rewards` is called.
5. In `calculate_staker_pools_rewards`: `pool_balance_18_decimals = 500 * 10^10 = 5e12 > 0`, so `pool_rewards > 0`.
6. In `update_pool_rewards`: STRK is transferred to the pool contract.
7. In `update_rewards_from_staking_contract`: `compute_rewards_per_unit(rewards, 500)` → `500 < 1000` → returns `0`. Sigma unchanged.
8. Delegator calls `claim_rewards` → receives 0 STRK.
9. The STRK sent in step 6 is permanently stuck in the pool contract with no recovery path.

### Citations

**File:** src/staking/staking.cairo (L1872-1887)
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
```

**File:** src/staking/staking.cairo (L1969-1988)
```text
                let pool_balance_curr_epoch = self
                    .get_staker_delegated_balance_at_epoch(
                        :staker_address, :pool_contract, epoch_id: curr_epoch,
                    );
                let (total_rewards, total_stake) = if token_address == STRK_TOKEN_ADDRESS {
                    (strk_total_rewards, strk_total_stake)
                } else {
                    (btc_total_rewards, btc_total_stake)
                };
                // Calculate rewards for this pool.
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
```

**File:** src/staking/staking.cairo (L1994-1999)
```text
                if pool_rewards.is_non_zero() {
                    pool_rewards_array
                        .append(
                            (pool_contract, token_address, pool_balance_curr_epoch, pool_rewards),
                        );
                }
```

**File:** src/pool/pool.cairo (L182-199)
```text
        fn enter_delegation_pool(
            ref self: ContractState, reward_address: ContractAddress, amount: Amount,
        ) {
            // Asserts.
            self.assert_staker_is_active();
            let pool_member = get_caller_address();
            assert!(
                self.pool_member_info.read(pool_member).is_none(), "{}", Error::POOL_MEMBER_EXISTS,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let token_dispatcher = self.token_dispatcher.read();
            let token_address = token_dispatcher.contract_address;
            assert!(token_address != pool_member, "{}", Error::POOL_MEMBER_IS_TOKEN);
            assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
            // Transfer funds from the delegator to the staking contract.
            let staker_address = self.staker_address.read();
            transfer_from_delegator(:pool_member, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);
```

**File:** src/pool/pool.cairo (L576-586)
```text
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

**File:** src/pool/utils.cairo (L131-138)
```text
        let decimals = token_dispatcher.decimals();
        assert!(decimals >= 5 && decimals <= 18, "{}", GenericError::INVALID_TOKEN_DECIMALS);
        TokenRewardsConfig {
            decimals,
            min_for_rewards: 10_u128.pow(decimals.into() - 5),
            base_value: 10_u128.pow(decimals.into() + 5),
        }
    }
```
