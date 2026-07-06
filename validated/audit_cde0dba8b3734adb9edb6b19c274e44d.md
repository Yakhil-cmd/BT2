### Title
Staker Can Instantly Increase Commission to 100% via Commitment Mechanism, Stealing Delegator Epoch Rewards — (File: `src/staking/staking.cairo`)

---

### Summary

A staker can atomically set a `CommissionCommitment` with `max_commission = 10000` (100%) and immediately call `set_commission(10000)` in the same block. Because `calculate_staker_pools_rewards` reads the commission directly from live storage at reward-calculation time — with no epoch-based delay — the staker can then trigger attestation to capture 100% of delegator rewards for that epoch, leaving delegators with zero yield.

---

### Finding Description

`set_commission` enforces two distinct paths depending on whether a `CommissionCommitment` is active:

- **No active commitment**: commission can only be *decreased* (`commission < old_commission`).
- **Active commitment**: commission can be set to *any* value ≤ `max_commission`, including an *increase*, as long as it differs from the current value. [1](#0-0) 

A staker can therefore:

1. Call `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)` — the minimum valid expiration is `current_epoch + 1`, so the commitment is immediately active.
2. In the very next transaction (same block), call `set_commission(commission: 10000)` — this passes the active-commitment branch and raises commission to 100%. [2](#0-1) 

The commission change takes effect **immediately**. `calculate_staker_pools_rewards` reads the commission from live storage at the moment rewards are computed — there is no epoch-based checkpoint or delay:

```cairo
let commission = staker_pool_info.commission();   // live storage read
...
let (commission_rewards, pool_rewards) = split_rewards_with_commission(
    rewards_including_commission: pool_rewards_including_commission, :commission,
);
``` [3](#0-2) 

The developers themselves acknowledge this gap in a code comment directly above `set_commission_commitment`:

> **Note**: Current commission increase safeguards still allow for sudden commission changes. [4](#0-3) 

After raising commission to 100%, the staker's operational address calls `attest`, which triggers `update_rewards_from_attestation_contract` → `_update_rewards` → `calculate_staker_pools_rewards`. All pool rewards are classified as `commission_rewards` and credited to the staker; `pool_rewards` becomes zero and nothing is transferred to the delegation pool. [5](#0-4) 

---

### Impact Explanation

Every delegator in the staker's pool(s) receives **zero rewards** for the epoch in which the attack is executed. The staker captures the full pool-reward share as commission. This is a direct theft of unclaimed yield from delegators — matching the **High: Theft of unclaimed yield** impact category.

---

### Likelihood Explanation

The attack requires only two permissionless transactions by the staker's own address, executable in the same block, with no external dependencies. The staker controls their operational address and can time the attestation call to immediately follow the commission change. Any staker with active delegators is capable of executing this. Likelihood is **High**.

---

### Recommendation

Introduce an epoch-based activation delay for commission *increases*. Specifically:

- Store the new (higher) commission alongside the epoch at which it becomes effective (e.g., `current_epoch + K`).
- In `calculate_staker_pools_rewards`, resolve the commission using the epoch-checkpoint mechanism already used for stake balances, so that a commission increase only applies to reward calculations starting from the activation epoch.
- Alternatively, prohibit commission increases entirely (only allow decreases), removing the commitment-based increase path.

---

### Proof of Concept

```
Epoch N, Block B:
  staker calls set_commission_commitment(max_commission=10000, expiration_epoch=N+1)
  staker calls set_commission(commission=10000)
    → passes active-commitment branch (10000 <= 10000, 10000 != old_commission)
    → staker_pool_info.commission is now 10000

  staker's operational_address calls attest(block_hash)
    → attestation contract calls update_rewards_from_attestation_contract(staker_address)
    → _update_rewards → calculate_staker_pools_rewards
         commission = staker_pool_info.commission()  // = 10000
         commission_rewards = pool_rewards_including_commission * 10000 / 10000
                            = pool_rewards_including_commission   // 100%
         pool_rewards = 0
    → send_rewards_to_delegation_pool(amount=0)   // delegators get nothing
    → staker.unclaimed_rewards_own += staker_own_rewards + commission_rewards
                                                  // staker gets everything

Result: delegators earn 0 STRK for epoch N; staker steals their full yield.
``` [6](#0-5) [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L725-743)
```text
        fn set_commission(ref self: ContractState, commission: Commission) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(commission <= COMMISSION_DENOMINATOR, "{}", Error::COMMISSION_OUT_OF_RANGE);
            let staker_address = get_caller_address();
            let staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);

            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            if let Option::Some(old_commission) = staker_pool_info.commission.read() {
                self
                    .update_commission(
                        :staker_address, :staker_pool_info, :old_commission, :commission,
                    );
            } else {
                staker_pool_info.commission.write(Option::Some(commission));
                self.emit(Events::CommissionInitialized { staker_address, commission });
            }
        }
```

**File:** src/staking/staking.cairo (L745-747)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
        /// **Note**: Updating epoch info can impact the commission commitment expiration date.
```

**File:** src/staking/staking.cairo (L748-784)
```text
        fn set_commission_commitment(
            ref self: ContractState, max_commission: Commission, expiration_epoch: Epoch,
        ) {
            self.general_prerequisites();
            assert!(max_commission <= COMMISSION_DENOMINATOR, "{}", Error::COMMISSION_OUT_OF_RANGE);
            let staker_address = get_caller_address();
            let staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            assert!(staker_pool_info.has_pool(), "{}", Error::MISSING_POOL_CONTRACT);
            let current_epoch = self.get_current_epoch();
            if let Option::Some(commission_commitment) = staker_pool_info
                .commission_commitment
                .read() {
                assert!(
                    !self.is_commission_commitment_active(:commission_commitment),
                    "{}",
                    Error::COMMISSION_COMMITMENT_EXISTS,
                );
            }
            // Staker must have a commission since it has a pool.
            let current_commission = staker_pool_info.commission();
            assert!(current_commission <= max_commission, "{}", Error::MAX_COMMISSION_TOO_LOW);
            assert!(expiration_epoch > current_epoch, "{}", Error::EXPIRATION_EPOCH_TOO_EARLY);
            assert!(
                expiration_epoch - current_epoch <= self.get_epoch_info().epochs_in_year(),
                "{}",
                Error::EXPIRATION_EPOCH_TOO_FAR,
            );
            let commission_commitment = CommissionCommitment { max_commission, expiration_epoch };
            staker_pool_info.commission_commitment.write(Option::Some(commission_commitment));
            self
                .emit(
                    Events::CommissionCommitmentSet {
                        staker_address, max_commission, expiration_epoch,
                    },
                );
```

**File:** src/staking/staking.cairo (L1580-1597)
```text
            if let Option::Some(commission_commitment) = staker_pool_info
                .commission_commitment
                .read() {
                if self.is_commission_commitment_active(:commission_commitment) {
                    assert!(
                        commission <= commission_commitment.max_commission,
                        "{}",
                        Error::INVALID_COMMISSION_WITH_COMMITMENT,
                    );
                    assert!(commission != old_commission, "{}", Error::INVALID_SAME_COMMISSION);
                } else {
                    assert!(
                        commission < old_commission, "{}", Error::COMMISSION_COMMITMENT_EXPIRED,
                    );
                }
            } else {
                assert!(commission < old_commission, "{}", Error::INVALID_COMMISSION);
            }
```

**File:** src/staking/staking.cairo (L1964-1999)
```text
            let commission = staker_pool_info.commission();
            for (pool_contract, token_address) in staker_pool_info.pools {
                if !self.is_active_token(:token_address, epoch_id: curr_epoch) {
                    continue;
                }
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

**File:** src/staking/staking.cairo (L2313-2365)
```text
        fn _update_rewards(
            ref self: ContractState,
            staker_address: ContractAddress,
            strk_total_rewards: Amount,
            btc_total_rewards: Amount,
            strk_total_stake: NormalizedAmount,
            btc_total_stake: NormalizedAmount,
            mut staker_info: InternalStakerInfoLatest,
            staker_pool_info: StoragePath<InternalStakerPoolInfoV2>,
            reward_supplier_dispatcher: IRewardSupplierDispatcher,
            curr_epoch: Epoch,
        ) {
            // Calculate self rewards.
            let staker_own_rewards = self
                .calculate_staker_own_rewards(
                    :staker_address, :strk_total_rewards, :strk_total_stake, :curr_epoch,
                );

            // Calculate pools rewards.
            let (commission_rewards, total_pools_rewards, pools_rewards_data) = if staker_pool_info
                .has_pool() {
                self
                    .calculate_staker_pools_rewards(
                        :staker_address,
                        :staker_pool_info,
                        :strk_total_rewards,
                        :strk_total_stake,
                        :btc_total_rewards,
                        :btc_total_stake,
                        :curr_epoch,
                    )
            } else {
                (Zero::zero(), Zero::zero(), array![])
            };

            // Update reward supplier.
            let staker_rewards = staker_own_rewards + commission_rewards;
            // Update total rewards.
            reward_supplier_dispatcher
                .update_unclaimed_rewards_from_staking_contract(
                    rewards: staker_rewards + total_pools_rewards,
                );
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
