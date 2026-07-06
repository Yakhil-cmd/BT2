### Title
No Commission Slippage Protection in `enter_delegation_pool` and `switch_delegation_pool` - (File: src/pool/pool.cairo)

### Summary
`enter_delegation_pool` and `switch_delegation_pool` in the Pool contract execute against the commission rate that is current at execution time, with no mechanism for delegators to specify a maximum acceptable commission. When a staker holds an active `CommissionCommitment`, they can legally increase their commission up to `max_commission` at any moment. A staker can front-run a delegator's entry or switch transaction, raising the commission to `max_commission` just before the delegator's transaction lands, causing the delegator to receive materially less yield than they observed when submitting the transaction.

### Finding Description
The `update_commission` internal function in `src/staking/staking.cairo` contains two distinct code paths:

- **Without an active commitment**: commission can only decrease (`commission < old_commission`).
- **With an active commitment**: commission can be set to any value up to `max_commission`, including a large increase. [1](#0-0) 

The code itself acknowledges this risk with a developer note: [2](#0-1) 

`enter_delegation_pool` accepts only `reward_address` and `amount`; there is no `max_commission` guard: [3](#0-2) 

`switch_delegation_pool` similarly accepts only `to_staker`, `to_pool`, and `amount`; no commission bound is checked: [4](#0-3) 

The `set_commission` entry point that a staker calls to raise commission is: [5](#0-4) 

And the `set_commission_commitment` entry point that enables the increase is: [6](#0-5) 

### Impact Explanation
A delegator who submits `enter_delegation_pool` or `switch_delegation_pool` after observing a low commission (e.g., 5 %) can be front-run by the staker calling `set_commission` to the commitment ceiling (e.g., 50 %). The delegator's transaction executes against the new, higher commission. All future rewards earned by that delegator are split at the elevated rate, with the excess flowing to the staker. This constitutes **theft of unclaimed yield** from the delegator.

The impact scales with:
- The size of the commission jump (`max_commission − current_commission`).
- The delegated amount and the duration the delegator remains in the pool before exiting (exit requires an intent + wait window, during which yield continues to be stolen).

This maps to **High: Theft of unclaimed yield**.

### Likelihood Explanation
The attack requires the staker to have a currently active `CommissionCommitment` with `max_commission` meaningfully above the advertised commission. This is a normal, permissionless operation any staker can perform. On Starknet's current single-sequencer architecture, a staker can observe the mempool and insert `set_commission` ahead of a delegator's transaction in the same block. Even without mempool visibility, a staker can advertise a low commission to attract delegators, set a commitment, and then raise commission immediately after delegators enter — the delegators are then locked in for the duration of the exit wait window.

### Recommendation
Add a `max_commission: Commission` parameter to both `enter_delegation_pool` and `switch_delegation_pool`. After the call resolves the current commission from storage, assert:

```rust
let current_commission = staking_dispatcher.get_commission(staker_address);
assert!(current_commission <= max_commission, Error::COMMISSION_TOO_HIGH);
```

This mirrors the Uniswap V2 `amountAMin`/`amountBMin` pattern cited in the external report and ensures delegators cannot be silently subjected to a commission higher than they accepted.

### Proof of Concept
1. Staker deploys with `commission = 500` (5 %).
2. Staker calls `set_commission_commitment(max_commission: 5000, expiration_epoch: current + 10)`.
3. Delegator observes `commission = 500` and submits `enter_delegation_pool(reward_address, amount)`.
4. Before the delegator's transaction is sequenced, the staker calls `set_commission(commission: 5000)`. This succeeds because an active commitment permits it. [7](#0-6) 
5. The delegator's `enter_delegation_pool` transaction executes. No commission check exists in the function body. [3](#0-2) 
6. All subsequent rewards for the delegator are computed at 50 % commission. The delegator receives 50 % of what they would have received at the advertised 5 % rate. The staker captures the difference as commission.

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

**File:** src/staking/staking.cairo (L745-746)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
```

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
