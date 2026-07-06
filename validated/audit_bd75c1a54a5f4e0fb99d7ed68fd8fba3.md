### Title
Commission Rate Can Be Increased Mid-Delegation via Commitment Mechanism, Stealing Delegator Yield - (File: src/staking/staking.cairo)

### Summary
A staker can attract delegators with a low commission rate, then use the `set_commission_commitment` + `set_commission` mechanism to immediately raise commission to any value up to `max_commission` (including 100%). Because commission is applied at reward-distribution time using the **current** rate, delegators who entered the pool under the original rate receive less yield than expected — up to zero — with no on-chain recourse before the exit window expires.

### Finding Description
The `set_commission_commitment` function allows a staker to set a `CommissionCommitment { max_commission, expiration_epoch }`. While an active commitment exists, `set_commission` permits the staker to set commission to **any value ≤ max_commission**, including values **higher** than the current commission. [1](#0-0) 

The only constraint when a commitment is active is `commission <= commitment.max_commission && commission != old_commission`. There is no minimum delay between setting the commitment and raising the commission. The code itself acknowledges this gap: [2](#0-1) 

Commission is read and applied at reward-distribution time (both attestation-based and consensus-based paths): [3](#0-2) 

There is no snapshot of the commission rate at the time a delegator enters the pool. The pool contract reads commission live from the staking contract: [4](#0-3) 

### Impact Explanation
A malicious staker can execute the following sequence atomically (or within a single block):

1. Operate with `commission = 0` to attract delegators.
2. Call `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)`.
3. Immediately call `set_commission(commission: 10000)`.

From this point forward, 100% of pool rewards are taken as commission. Delegators receive zero yield. Because the exit window (`exit_wait_window`) forces delegators to wait before withdrawing principal, all rewards accrued during that window are also lost. This constitutes **theft of unclaimed yield** (High severity per the allowed impact scope). [5](#0-4) 

### Likelihood Explanation
The attack is fully permissionless from the staker's side. No privileged role, leaked key, or external dependency is required. The staker is the natural controller of commission. The commitment mechanism was designed to allow increases, so no invariant is broken — the vulnerability is the absence of a time-lock or delegator-protection window between commitment creation and commission increase. The flow test `DelegatorDidntUpdateAfterStakerUpdateCommissionFlow` in the test suite already demonstrates that commission changes affect delegator rewards retroactively: [6](#0-5) 

### Recommendation
Introduce a mandatory delay (e.g., at least one full epoch) between the moment a `CommissionCommitment` is set and the moment a commission **increase** can take effect. This gives delegators an observable window to exit before the higher rate applies. Alternatively, lock the commission rate for each delegator at the epoch they entered the pool, analogous to how the external Sofa Protocol report recommends including the fee in the product ID hash.

### Proof of Concept
Attack path (Cairo pseudocode):

```
// Step 1: Staker stakes with 0% commission, attracts delegators.
staking.set_commission(commission: 0);
staking.set_open_for_delegation(token_address: STRK);
// Delegators enter pool expecting 0% commission.
pool.enter_delegation_pool(reward_address, amount);

// Step 2: Staker sets commitment with max = 100%, expiring next epoch.
staking.set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1);

// Step 3: Staker immediately raises commission to 100% — same block.
staking.set_commission(commission: 10000);

// Step 4: Next reward distribution — delegators receive 0 STRK.
// update_rewards_from_attestation_contract / update_rewards reads commission = 10000.
// split_rewards_with_commission returns (pool_rewards, 0) for delegators.

// Step 5: Delegators call exit_delegation_pool_intent but must wait exit_wait_window.
// All rewards during the wait window are also taken at 100% commission.
```

The root cause is in `update_commission` (`src/staking/staking.cairo` lines 1573–1609) which permits immediate commission increases under an active commitment, and in `calculate_staker_pools_rewards` (`src/staking/staking.cairo` lines 1949–2001) which applies the live commission at distribution time with no reference to the rate at delegation entry. [7](#0-6) [8](#0-7)

### Citations

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

**File:** src/staking/staking.cairo (L1573-1609)
```text
        fn update_commission(
            ref self: ContractState,
            staker_address: ContractAddress,
            staker_pool_info: StoragePath<Mutable<InternalStakerPoolInfoV2>>,
            old_commission: Commission,
            commission: Commission,
        ) {
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

            // Update commission in storage.
            staker_pool_info.commission.write(Option::Some(commission));

            // Emit event.
            self
                .emit(
                    Events::CommissionChanged {
                        staker_address, old_commission, new_commission: commission,
                    },
                );
        }
```

**File:** src/staking/staking.cairo (L1949-2001)
```text
        fn calculate_staker_pools_rewards(
            self: @ContractState,
            staker_address: ContractAddress,
            staker_pool_info: StoragePath<InternalStakerPoolInfoV2>,
            strk_total_rewards: Amount,
            strk_total_stake: NormalizedAmount,
            btc_total_rewards: Amount,
            btc_total_stake: NormalizedAmount,
            curr_epoch: Epoch,
        ) -> (Amount, Amount, Array<(ContractAddress, ContractAddress, NormalizedAmount, Amount)>) {
            // Array for rewards data needed to update pools.
            // Contains tuples of (pool_contract, token_address, pool_balance, pool_rewards).
            let mut pool_rewards_array = array![];
            let mut total_commission_rewards: Amount = Zero::zero();
            let mut total_pools_rewards: Amount = Zero::zero();
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
            }
            (total_commission_rewards, total_pools_rewards, pool_rewards_array)
```

**File:** src/pool/pool.cairo (L935-948)
```text
        fn get_commission_from_staking_contract(self: @ContractState) -> Commission {
            if self.staker_removed.read() {
                return Zero::zero();
            }
            let staking_dispatcher = IStakingDispatcher {
                contract_address: self.staking_pool_dispatcher.contract_address.read(),
            };
            // The staker must have commission since it has a pool (this contract). So unwrap is
            // safe.
            staking_dispatcher
                .staker_pool_info(staker_address: self.staker_address.read())
                .commission
                .unwrap()
        }
```

**File:** src/flow_test/flows.cairo (L811-870)
```text
> {
    fn test(self: DelegatorDidntUpdateAfterStakerUpdateCommissionFlow, ref system: SystemState) {
        let initial_reward_supplier_balance = system
            .token
            .balance_of(account: system.reward_supplier.address);
        let min_stake = system.staking.get_min_stake();
        let stake_amount = min_stake * 2;
        let delegated_amount = stake_amount;
        let staker = system.new_staker(amount: stake_amount);
        let delegator = system.new_delegator(amount: delegated_amount);
        let commission = 10000;

        // Stake with commission 100%
        system.stake(:staker, amount: stake_amount, pool_enabled: true, :commission);
        system.advance_k_epochs_and_attest(:staker);

        let pool = system.staking.get_pool(:staker);
        system.delegate(:delegator, :pool, amount: delegated_amount);

        // Update commission to 0%
        system.set_commission(:staker, commission: Zero::zero());
        system.advance_k_epochs_and_attest(:staker);

        system.delegator_exit_intent(:delegator, :pool, amount: delegated_amount);
        system.advance_time(time: system.staking.get_exit_wait_window());
        system.advance_k_epochs_and_attest(:staker);
        system.delegator_exit_action(:delegator, :pool);
        system.delegator_claim_rewards(:delegator, :pool);

        // Clean up and make all parties exit.
        system.staker_exit_intent(:staker);
        system.advance_time(time: system.staking.get_exit_wait_window());
        system.staker_exit_action(:staker);

        // ------------- Flow complete, now asserts -------------

        // Assert pool balance is zero.
        assert!(system.token.balance_of(account: pool) == 0);

        // Assert all staked amounts were transferred back.
        assert!(system.token.balance_of(account: system.staking.address).is_zero());
        assert!(system.token.balance_of(account: staker.staker.address) == stake_amount);
        assert!(system.token.balance_of(account: delegator.delegator.address) == delegated_amount);

        // Assert staker reward address is not empty.
        assert!(system.token.balance_of(account: staker.reward.address).is_non_zero());

        assert!(system.token.balance_of(account: delegator.reward.address).is_non_zero());

        // Assert all funds that moved from rewards supplier, were moved to correct addresses.
        assert!(wide_abs_diff(system.reward_supplier.get_unclaimed_rewards(), STRK_IN_FRIS) < 100);
        assert!(
            initial_reward_supplier_balance == system
                .token
                .balance_of(account: system.reward_supplier.address)
                + system.token.balance_of(account: staker.reward.address)
                + system.token.balance_of(account: delegator.reward.address),
        );
    }
}
```
