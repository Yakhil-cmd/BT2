### Title
Rewards Permanently Frozen in Pool Contract When Pool Balance Falls Below `min_delegation_for_rewards` — (File: `src/pool/pool.cairo`)

### Summary

The Pool contract's `compute_rewards_per_unit` silently returns zero when `total_stake < min_delegation_for_rewards`, but the staking contract unconditionally transfers `pool_rewards` STRK tokens to the pool contract before calling `update_rewards_from_staking_contract`. Because the cumulative rewards trace is never updated in this case, the transferred STRK is permanently unclaimable by any pool member. An unprivileged delegator can deliberately trigger this condition by exiting their delegation to push the remaining pool balance below the threshold, permanently freezing the yield of all remaining delegators.

---

### Finding Description

In `src/pool/pool.cairo`, `compute_rewards_per_unit` guards against division-by-small-denominator overflow by returning zero when `total_stake < min_delegation_for_rewards`:

```cairo
fn compute_rewards_per_unit(
    self: @ContractState, staking_rewards: Amount, total_stake: Amount,
) -> Index {
    if total_stake < self.min_delegation_for_rewards.read() {
        return Zero::zero();
    }
    ...
}
``` [1](#0-0) 

For STRK pools, `min_delegation_for_rewards = 10^18` (1 STRK). For BTC pools with 8 decimals, it is `10^3` satoshis. [2](#0-1) 

`update_rewards_from_staking_contract` calls `compute_rewards_per_unit` and inserts the result into the cumulative rewards trace:

```cairo
fn update_rewards_from_staking_contract(
    ref self: ContractState, rewards: Amount, pool_balance: Amount,
) {
    self.assert_caller_is_staking_contract();
    let (_, last) = self.cumulative_rewards_trace.last().unwrap();
    self.cumulative_rewards_trace.insert(
        key: self.get_current_epoch(),
        value: last + self.compute_rewards_per_unit(
            staking_rewards: rewards, total_stake: pool_balance,
        ),
    );
}
``` [3](#0-2) 

However, in the staking contract, `update_pool_rewards` **unconditionally** transfers `pool_rewards` STRK to the pool contract **before** calling `update_rewards_from_staking_contract`:

```cairo
self.send_rewards_to_delegation_pool(
    :staker_address,
    pool_address: pool_contract,
    amount: pool_rewards,
    token_dispatcher: strk_token_dispatcher,
);
...
pool_dispatcher.update_rewards_from_staking_contract(
    rewards: pool_rewards,
    pool_balance: pool_balance.to_native_amount(:decimals),
);
``` [4](#0-3) 

When `pool_balance < min_delegation_for_rewards`, the STRK tokens arrive in the pool contract but `compute_rewards_per_unit` returns zero, so the cumulative trace is not advanced. No pool member can ever claim these tokens — they are permanently frozen. The code comment itself acknowledges this:

> **Note**: Delegation rewards lost when pool balance is less than `min_delegation_for_rewards`. The staking contract continues to forward `pool_rewards` to the pool contract even in this case. [5](#0-4) 

---

### Impact Explanation

Any STRK forwarded to a pool contract during an epoch where `pool_balance < min_delegation_for_rewards` is permanently unclaimable. The pool contract has no administrative sweep function; `claim_rewards`, `exit_delegation_pool_action`, and `transfer_to_pools_when_unstake` all operate on tracked balances and the cumulative trace — none can recover untracked STRK. This constitutes **permanent freezing of unclaimed yield** (High impact).

---

### Likelihood Explanation

For STRK pools the threshold is 1 STRK — a realistic value for small or newly-created pools. An attacker who is a delegator in a pool with a combined remaining balance just above 1 STRK can call `exit_delegation_pool_intent` to reduce the pool balance below the threshold. After the K-epoch delay the balance takes effect, and the next reward distribution permanently freezes the remaining delegators' yield. The attacker needs no special privilege — only a valid delegation in the target pool. The attack is repeatable every epoch.

---

### Recommendation

In `update_pool_rewards` (staking contract), skip the `send_rewards_to_delegation_pool` call when the pool balance is below `min_delegation_for_rewards`, mirroring the zero-return guard already present in `compute_rewards_per_unit`. Alternatively, accumulate the untracked rewards into the staker's own reward balance or return them to the reward supplier, so no STRK is ever transferred to a pool whose trace will not be updated.

---

### Proof of Concept

1. Staker S opens a STRK delegation pool.
2. Alice delegates 0.9 STRK; Bob (attacker) delegates 0.2 STRK. Pool balance = 1.1 STRK (above threshold).
3. Bob calls `exit_delegation_pool_intent(amount: 0.2 STRK)`.
4. After K epochs the pool balance becomes 0.9 STRK < `min_delegation_for_rewards` (1 STRK).
5. Attestation/`update_rewards` fires. `calculate_staker_pools_rewards` computes `pool_rewards > 0` (0.9 STRK / total_stake × epoch_rewards).
6. `send_rewards_to_delegation_pool` transfers those STRK to the pool contract.
7. `update_rewards_from_staking_contract` is called; `compute_rewards_per_unit` returns 0 because `0.9 × 10^18 < 10^18`.
8. The cumulative trace is unchanged. Alice calls `claim_rewards` and receives 0. The STRK tokens sit in the pool contract with no mechanism to recover them.

### Citations

**File:** src/pool/pool.cairo (L62-64)
```text
    pub(crate) const STRK_CONFIG: TokenRewardsConfig = TokenRewardsConfig {
        decimals: 18, min_for_rewards: 10_u128.pow(18), base_value: 10_u128.pow(28),
    };
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

**File:** src/staking/staking.cairo (L1875-1887)
```text
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
