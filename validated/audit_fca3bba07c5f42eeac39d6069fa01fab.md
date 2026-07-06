### Title
Lack of Maximum Commission Guard in `enter_delegation_pool` / `add_to_delegation_pool` Allows Staker to Front-Run Delegators - (File: src/pool/pool.cairo)

---

### Summary
`enter_delegation_pool` and `add_to_delegation_pool` in `src/pool/pool.cairo` accept no `max_commission` parameter. A staker who holds an active `CommissionCommitment` can atomically raise their commission up to `max_commission` in the same block as a delegator's deposit, causing the delegator to earn far less yield than they expected with no ability to revert.

---

### Finding Description

The `set_commission_commitment` mechanism in `src/staking/staking.cairo` explicitly allows a staker to pre-commit to a ceiling (`max_commission`) and then call `set_commission` to raise the live commission to any value up to that ceiling while the commitment is active. [1](#0-0) 

The `update_commission` internal function enforces that without a commitment the commission can only decrease, but with an active commitment it may be raised up to `max_commission`: [2](#0-1) 

The pool-side entry points that a delegator calls contain no commission guard whatsoever: [3](#0-2) [4](#0-3) 

The function signatures are:

```cairo
fn enter_delegation_pool(
    ref self: ContractState, reward_address: ContractAddress, amount: Amount,
)
fn add_to_delegation_pool(
    ref self: ContractState, pool_member: ContractAddress, amount: Amount,
) -> Amount
```

Neither accepts a `max_commission` argument. The commission that will actually be applied to the delegator's future rewards is read from staking-contract storage at reward-calculation time, not at deposit time, so the delegator has no on-chain protection against a commission change that occurs between their transaction submission and its execution.

The same gap exists in `switch_delegation_pool`, where a delegator switching to a destination pool has no way to assert the destination pool's commission: [5](#0-4) 

---

### Impact Explanation

A delegator who deposits expecting a 5 % commission but whose transaction is mined after the staker raises commission to 50 % will permanently earn only half the yield they anticipated for the entire duration they remain in the pool. This constitutes **theft of unclaimed yield** (High severity per the allowed impact scope). The delegator's only recourse is to exit, which requires waiting through the full `exit_wait_window` (default one week), during which they continue to earn at the inflated commission rate.

---

### Likelihood Explanation

- Starknet currently uses a centralized sequencer, making transaction ordering manipulation straightforward for a staker who monitors the pending transaction queue.
- Even without deliberate front-running, a staker can raise commission at any time while a commitment is active; any delegator whose transaction was in-flight at that moment is silently harmed.
- The `CommissionCommitment` is publicly visible on-chain, so a staker can pre-announce the ceiling and then execute the raise the moment a large delegation appears.
- The staker has a direct financial incentive: higher commission means more of the pool's rewards flow to the staker.

---

### Recommendation

Add a `max_commission` parameter to `enter_delegation_pool`, `add_to_delegation_pool`, and `switch_delegation_pool`. At the start of each function, read the current commission from the staking contract and assert it does not exceed the caller-supplied ceiling:

```cairo
fn enter_delegation_pool(
    ref self: ContractState,
    reward_address: ContractAddress,
    amount: Amount,
    max_commission: Commission,   // <-- new
) {
    let current_commission = self.staking_pool_dispatcher.read().get_commission(...);
    assert!(current_commission <= max_commission, "Commission exceeds max acceptable");
    // ... rest of function unchanged
}
```

This mirrors the standard slippage-protection pattern and gives delegators an atomic, trustless guarantee about the terms under which their funds are committed.

---

### Proof of Concept

1. Staker calls `set_commission(5%)` — current commission is 5 %.
2. Staker calls `set_commission_commitment(max_commission: 5000, expiration_epoch: current+10)` — commitment ceiling is 50 %. [6](#0-5) 
3. Delegator observes 5 % commission and submits `enter_delegation_pool(reward_address, 1_000_000)`.
4. Before the delegator's transaction is sequenced, the staker submits `set_commission(5000)` — raises commission to 50 %. [7](#0-6) 
5. The sequencer orders the staker's `set_commission` first (trivial with a centralized sequencer).
6. The delegator's `enter_delegation_pool` executes successfully — no commission check exists. [8](#0-7) 
7. From this point forward, 50 % of all pool rewards are taken as commission instead of 5 %, permanently reducing the delegator's yield by ~47 percentage points with no on-chain recourse until they complete the full exit window.

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

**File:** src/staking/staking.cairo (L1591-1600)
```text
                    assert!(
                        commission < old_commission, "{}", Error::COMMISSION_COMMITMENT_EXPIRED,
                    );
                }
            } else {
                assert!(commission < old_commission, "{}", Error::INVALID_COMMISSION);
            }

            // Update commission in storage.
            staker_pool_info.commission.write(Option::Some(commission));
```

**File:** src/pool/pool.cairo (L181-219)
```text
    impl PoolImpl of IPool<ContractState> {
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

**File:** src/pool/pool.cairo (L221-245)
```text
        fn add_to_delegation_pool(
            ref self: ContractState, pool_member: ContractAddress, amount: Amount,
        ) -> Amount {
            // Asserts.
            self.assert_staker_is_active();
            let pool_member_info = self.internal_pool_member_info(:pool_member);
            let caller_address = get_caller_address();
            assert!(
                caller_address == pool_member || caller_address == pool_member_info.reward_address,
                "{}",
                Error::CALLER_CANNOT_ADD_TO_POOL,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);

            // Transfer funds from the delegator to the staking contract.
            let token_dispatcher = self.token_dispatcher.read();
            let staker_address = self.staker_address.read();
            transfer_from_delegator(pool_member: caller_address, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);

            // Update the pool member's balance checkpoint.
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
            let new_delegated_stake = old_delegated_stake + amount;

            // Emit events.
```

**File:** src/pool/pool.cairo (L391-428)
```text
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
```
