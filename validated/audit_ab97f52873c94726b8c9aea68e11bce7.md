### Title
Delegator Enters Pool Without Commission Slippage Check, Enabling Staker Front-Run to Steal Yield - (File: src/pool/pool.cairo)

### Summary
`enter_delegation_pool` and `switch_delegation_pool` in `pool.cairo` accept no `expected_commission` parameter. A staker holding an active `commission_commitment` can atomically raise their commission to `max_commission` (up to 100%) in the same block as a delegator's delegation transaction, causing the delegator to unknowingly delegate under a commission rate they never agreed to, permanently redirecting all future yield to the staker.

### Finding Description

`enter_delegation_pool` and `switch_delegation_pool` in `pool.cairo` do not verify the commission rate of the target staker at execution time. [1](#0-0) [2](#0-1) 

Neither function accepts a `max_commission` or `expected_commission` parameter. The commission is stored in the staking contract and is read only when rewards are distributed, not when delegation occurs.

A staker can increase their commission above the current value if and only if an active `commission_commitment` exists. The `update_commission` internal function enforces: [3](#0-2) 

When a `commission_commitment` is active, `commission <= commission_commitment.max_commission` is the only constraint — the staker can raise commission to any value up to `max_commission`, including 100% (`10000`).

A staker can set a commitment and immediately raise commission in two sequential transactions within the same block:

1. `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)`
2. `set_commission(commission: 10000)` [4](#0-3) [5](#0-4) 

If the delegator's `enter_delegation_pool` or `switch_delegation_pool` transaction is ordered after these two staker transactions in the same block, the delegator is now locked into a pool with 100% commission. All future rewards from that staker flow entirely to the staker's reward address, with zero yield reaching the delegator.

### Impact Explanation

**High — Theft of unclaimed yield.**

With 100% commission, every reward epoch the staker earns rewards, the pool contract receives `0` (the entire reward is retained by the staker). The delegator's `claim_rewards` call will return zero for all future epochs. The delegator's principal is not stolen (they can exit), but all yield they would have earned is permanently redirected to the staker for as long as they remain in the pool. This matches the allowed impact: *Theft of unclaimed yield*. [6](#0-5) 

### Likelihood Explanation

**Medium.**

The attack requires the staker to:
1. Have previously set (or atomically set) a `commission_commitment` with a high `max_commission`.
2. Order their `set_commission_commitment` + `set_commission` transactions before the delegator's transaction in the same block.

On Starknet, transaction ordering within a block is controlled by the sequencer. A staker who monitors the mempool (or who is the sequencer) can reliably front-run. Even without deliberate front-running, a staker can raise commission in the same block a delegator enters, which can occur naturally during high-activity periods. The `commission_commitment` mechanism is a publicly visible, legitimate protocol feature, so no privileged access is required.

### Recommendation

Add an `expected_max_commission: Commission` parameter to `enter_delegation_pool` and `switch_delegation_pool`. At execution time, read the staker's current commission from the staking contract and assert it does not exceed `expected_max_commission`. This mirrors the fix recommended in the external report: pass the expected state as an input and verify it matches the on-chain state at execution time.

```cairo
fn enter_delegation_pool(
    ref self: ContractState,
    reward_address: ContractAddress,
    amount: Amount,
    expected_max_commission: Commission, // NEW
) {
    let current_commission = self.get_commission_from_staking_contract();
    assert!(
        current_commission <= expected_max_commission,
        "Commission exceeds expected maximum"
    );
    // ... rest of function
}
```

Apply the same guard to `switch_delegation_pool`.

### Proof of Concept

1. Staker deploys a pool with commission = 500 (5%).
2. Staker calls `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)`.
3. In the same block, staker calls `set_commission(commission: 10000)` — succeeds because active commitment allows it.
4. In the same block (ordered after steps 2–3), delegator calls `enter_delegation_pool(reward_address, amount: 1_000_000e18)`.
5. Delegation succeeds with no revert — no commission check exists.
6. Next reward epoch: staker attests, `_update_rewards` is called. The pool receives `pool_rewards = total_rewards * (1 - commission/10000) = total_rewards * 0 = 0`.
7. Delegator calls `claim_rewards` → receives `0` STRK.
8. All yield has been redirected to the staker's reward address. [7](#0-6)

### Citations

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

**File:** src/pool/pool.cairo (L379-418)
```text
        fn switch_delegation_pool(
            ref self: ContractState,
            to_staker: ContractAddress,
            to_pool: ContractAddress,
            amount: Amount,
        ) -> Amount {
            // Asserts.
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            assert!(
                pool_member_info.unpool_time.is_some(),
                "{}",
                GenericError::MISSING_UNDELEGATE_INTENT,
            );
            assert!(amount <= pool_member_info.unpool_amount, "{}", GenericError::AMOUNT_TOO_HIGH);
            let reward_address = pool_member_info.reward_address;

            // Update pool_member_info and write to storage.
            pool_member_info.unpool_amount -= amount;
            if pool_member_info.unpool_amount.is_zero() {
                // unpool_amount is zero, clear unpool_time.
                pool_member_info.unpool_time = Option::None;
            }
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Serialize the switch pool data and invoke the staking contract to switch pool.
            let switch_pool_data = SwitchPoolData { pool_member, reward_address };
            let mut serialized_data = array![];
            switch_pool_data.serialize(ref output: serialized_data);
            self
                .staking_pool_dispatcher
                .read()
                .switch_staking_delegation_pool(
                    :to_staker,
                    :to_pool,
                    switched_amount: amount,
                    data: serialized_data.span(),
                    identifier: pool_member.into(),
                );
```

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

**File:** src/staking/staking.cairo (L748-778)
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
