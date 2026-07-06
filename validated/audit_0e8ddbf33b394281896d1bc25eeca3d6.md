### Title
Precision Loss in `compute_rewards_per_unit` Causes Permanent Accumulation of Irrecoverable Yield in Pool Contracts - (File: src/pool/pool.cairo)

---

### Summary

The `Pool` contract's `compute_rewards_per_unit` function uses integer division that causes a residual amount of reward tokens to become permanently stuck in each pool contract. Real STRK tokens are transferred to the pool on every reward distribution, but the sigma-based accounting cannot represent the full amount, leaving a small but permanently irrecoverable residual that accumulates with every epoch.

---

### Finding Description

When the staking contract distributes rewards to a pool, it:

1. Transfers `pool_rewards` STRK tokens to the pool contract via `send_rewards_to_delegation_pool`.
2. Calls `update_rewards_from_staking_contract(rewards, pool_balance)` on the pool.

Inside `update_rewards_from_staking_contract`, the pool updates its cumulative sigma:

```cairo
fn update_rewards_from_staking_contract(
    ref self: ContractState, rewards: Amount, pool_balance: Amount,
) {
    let (_, last) = self.cumulative_rewards_trace.last().unwrap();
    self.cumulative_rewards_trace.insert(
        key: self.get_current_epoch(),
        value: last + self.compute_rewards_per_unit(
            staking_rewards: rewards, total_stake: pool_balance,
        ),
    );
}
``` [1](#0-0) 

`compute_rewards_per_unit` computes:

```cairo
fn compute_rewards_per_unit(
    self: @ContractState, staking_rewards: Amount, total_stake: Amount,
) -> Index {
    if total_stake < self.min_delegation_for_rewards.read() {
        return Zero::zero();
    }
    mul_wide_and_div(
        lhs: staking_rewards, rhs: self.staking_rewards_base_value.read(), div: total_stake,
    )
        .expect_with_err(err: InternalError::REWARDS_COMPUTATION_OVERFLOW)
}
``` [2](#0-1) 

This computes `floor(staking_rewards * base_value / total_stake)`. The floor division discards the remainder `(staking_rewards * base_value) % total_stake`. When pool members later claim rewards via `compute_rewards_rounded_down(amount * sigma / base_value)`, the total claimable across all members is strictly less than `pool_rewards`. The difference — `pool_rewards - sum(member_rewards)` — remains in the pool contract with no recovery path.

The staking contract's `_update_rewards` confirms that real tokens are transferred to the pool contract equal to `total_pools_rewards`:

```cairo
claim_from_reward_supplier(
    :reward_supplier_dispatcher,
    amount: total_pools_rewards,
    token_dispatcher: strk_token_dispatcher(),
);
// ...
let pool_rewards_list = self.update_pool_rewards(:staker_address, :pools_rewards_data);
``` [3](#0-2) 

The pool contract itself has no sweep or recovery function for residual token balances.

---

### Impact Explanation

Every epoch, for every active pool, a small residual of STRK tokens is transferred into the pool contract but can never be claimed by any pool member. These amounts accumulate permanently. The pool contract has no administrative function to recover stuck tokens. This constitutes **permanent freezing of unclaimed yield**.

The protocol's own test suite explicitly acknowledges this residual:

```cairo
assert!(pool_rewards_for_epoch == rewards
    + token_dispatcher.balance_of(pool_contract).try_into().unwrap());
assert!(token_dispatcher.balance_of(pool_contract) < 100);
``` [4](#0-3) 

The same pattern appears for BTC pools: [5](#0-4) 

The residual per epoch is bounded by `total_stake / base_value` FRI, which is small per epoch but accumulates across all pools and all epochs indefinitely.

---

### Likelihood Explanation

**High.** The precision loss occurs on every single call to `update_rewards_from_staking_contract`, which is invoked every epoch for every pool that has active delegators. There is no configuration or input that avoids it; it is structural to the integer arithmetic.

---

### Recommendation

Track the undistributed residual per epoch and carry it forward to the next reward distribution, analogous to the recommendation in the external report. Specifically, store `(staking_rewards * base_value) % total_stake` and add it (scaled back) to the next epoch's `staking_rewards` before computing the new sigma increment. This ensures no tokens transferred to the pool contract are permanently unclaimable.

---

### Proof of Concept

The existing test at `src/pool/tests/test.cairo` already demonstrates the issue:

```cairo
// After all pool members claim rewards:
assert!(pool_rewards_for_epoch == rewards
    + token_dispatcher.balance_of(pool_contract).try_into().unwrap());
// pool_contract holds a non-zero residual with no way to recover it:
assert!(token_dispatcher.balance_of(pool_contract) < 100);
``` [6](#0-5) 

The flow is:
1. Staking contract transfers `pool_rewards_for_epoch` tokens to the pool contract.
2. Pool contract updates sigma via `compute_rewards_per_unit` (floor division).
3. Pool member claims all available rewards — receives `rewards < pool_rewards_for_epoch`.
4. `pool_rewards_for_epoch - rewards` FRI remains in the pool contract permanently.

This repeats every epoch for every pool, causing irrecoverable yield to accumulate in each pool contract over the protocol's lifetime. [7](#0-6) [1](#0-0)

### Citations

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

**File:** src/staking/staking.cairo (L2355-2365)
```text
            // Claim pools rewards.
            claim_from_reward_supplier(
                :reward_supplier_dispatcher,
                amount: total_pools_rewards,
                token_dispatcher: strk_token_dispatcher(),
            );
            // Update staker rewards.
            staker_info.unclaimed_rewards_own += staker_rewards;

            // Update pools rewards.
            let pool_rewards_list = self.update_pool_rewards(:staker_address, :pools_rewards_data);
```

**File:** src/pool/tests/test.cairo (L692-700)
```text
    assert!(
        pool_rewards_for_epoch == rewards
            + token_dispatcher.balance_of(pool_contract).try_into().unwrap(),
    );
    assert!(token_dispatcher.balance_of(pool_contract) < 100);
    assert!(
        token_dispatcher.balance_of(cfg.pool_member_info.reward_address) == balance_before_claim
            + rewards.into(),
    );
```

**File:** src/pool/tests/test.cairo (L817-821)
```text
    assert!(
        pool_rewards_for_epoch == rewards
            + token_dispatcher.balance_of(pool_contract).try_into().unwrap(),
    );
    assert!(token_dispatcher.balance_of(pool_contract) < 100);
```
