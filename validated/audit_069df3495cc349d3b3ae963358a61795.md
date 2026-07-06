### Title
Missing `max_commission` Guard in `enter_delegation_pool` and `switch_delegation_pool` Allows Staker to Front-Run Delegators with a Commission Increase - (File: src/pool/pool.cairo)

---

### Summary

`enter_delegation_pool` and `switch_delegation_pool` accept no `max_commission` parameter. A staker who holds an active `commission_commitment` can legally raise their commission (up to `max_commission`) at any time. A delegator who reads the current commission off-chain and submits a delegation or pool-switch transaction can have that transaction execute against a materially higher commission than they observed, with no on-chain protection.

---

### Finding Description

`set_commission` in `staking.cairo` calls `update_commission`, which enforces the following rule:

> When a `commission_commitment` is active, the staker may set commission to **any** value ≤ `max_commission`, including values **higher** than the current commission. [1](#0-0) 

This is the only path in the protocol where commission can increase. It is a deliberate, documented feature.

`enter_delegation_pool` in `pool.cairo` takes only `reward_address` and `amount`: [2](#0-1) 

`switch_delegation_pool` takes only `to_staker`, `to_pool`, and `amount`: [3](#0-2) 

Neither function accepts a `max_commission` argument. There is no on-chain check that the commission at execution time matches what the delegator observed when constructing the transaction.

---

### Impact Explanation

Commission is deducted from every epoch's pool rewards before they are distributed to delegators. A delegator who joins or switches to a pool expecting 10% commission but executes against 50% commission will permanently earn less yield for every epoch they remain in that pool. This constitutes **theft of unclaimed yield**: the excess commission flows to the staker's reward address rather than the delegator's.

The loss is not a one-time event — it compounds over every future epoch until the delegator notices and exits (which itself requires waiting through the `exit_wait_window`). [4](#0-3) 

---

### Likelihood Explanation

The precondition is that the staker has called `set_commission_commitment` with a `max_commission` meaningfully above the current commission and the commitment has not yet expired. [5](#0-4) 

This is a normal, incentivized protocol action: stakers use commitments to attract delegators by promising a commission ceiling, then may raise commission within that ceiling. The window between a delegator reading the commission and their transaction being sequenced is sufficient for the staker to call `set_commission` first — either by monitoring the sequencer's pending transaction queue or simply by racing the delegator. On Starknet, the sequencer is currently centralised, making ordering trivially controllable by a colluding or malicious sequencer, but even without sequencer collusion the staker can submit their `set_commission` transaction in the same block before the delegator's transaction is included.

---

### Recommendation

Add a `max_commission` parameter to both `enter_delegation_pool` and `switch_delegation_pool` and assert it at execution time:

```cairo
fn enter_delegation_pool(
    ref self: ContractState,
    reward_address: ContractAddress,
    amount: Amount,
+   max_commission: Commission,
) {
    ...
+   let current_commission = self.get_commission_from_staking_contract();
+   assert!(current_commission <= max_commission, "Commission exceeds max_commission");
    ...
}
```

Apply the same guard to `switch_delegation_pool`. [6](#0-5) [7](#0-6) 

---

### Proof of Concept

1. Staker calls `set_commission_commitment(max_commission: 5000, expiration_epoch: current + 10)` with current commission at 500 (5%).
2. Delegator observes 5% commission on-chain and constructs a `switch_delegation_pool(to_staker, to_pool, amount)` transaction.
3. Staker calls `set_commission(5000)` (50%) — permitted because an active commitment exists and `5000 <= max_commission`. [8](#0-7) 
4. Staker's `set_commission` transaction is sequenced before the delegator's `switch_delegation_pool`.
5. Delegator's transaction executes. No commission check exists in `switch_delegation_pool`. [9](#0-8) 
6. Delegator is now in the pool at 50% commission. Every subsequent epoch, half of their share of pool rewards is taken by the staker instead of being forwarded to the delegator's `reward_address`. [10](#0-9)

### Citations

**File:** src/staking/staking.cairo (L748-785)
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
        }
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

**File:** src/pool/pool.cairo (L182-219)
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

            self.set_member_balance(:pool_member, :amount);

            // Create the pool member record.
            self
                .pool_member_info
                .write(pool_member, VInternalPoolMemberInfoTrait::new_latest(:reward_address));

            // Emit events.
            self
                .emit(
                    Events::NewPoolMember { pool_member, staker_address, reward_address, amount },
                );
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake: Zero::zero(), new_delegated_stake: amount,
                    },
                );
        }
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

**File:** src/pool/pool.cairo (L379-429)
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

            // Emit event.
            self
                .emit(
                    Events::SwitchDelegationPool {
                        pool_member, new_delegation_pool: to_pool, amount,
                    },
                );

            pool_member_info.unpool_amount
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
