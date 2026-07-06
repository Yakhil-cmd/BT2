### Title
Missing Commission Slippage Check in `switch_delegation_pool` Allows Staker to Front-Run Delegators - (File: src/pool/pool.cairo)

### Summary
`switch_delegation_pool` and `enter_delegation_pool` in `src/pool/pool.cairo` accept no `max_commission` parameter. A staker holding an active `CommissionCommitment` can atomically raise their commission to `max_commission` immediately before a delegator's pool-switch or pool-entry transaction executes, causing the delegator to land in a pool with a far higher commission rate than anticipated — an exact analog of the missing slippage check described in the external report.

---

### Finding Description

**Root cause — two cooperating code paths:**

**Path 1 — commission can be raised to `max_commission` in a single call.**

`set_commission` in `src/staking/staking.cairo` delegates to `update_commission`: [1](#0-0) 

When a `CommissionCommitment` is active, the only constraint is `commission <= max_commission`. A staker who previously called `set_commission_commitment(max_commission: 9000, ...)` with a current commission of `200` can jump to `9000` (90 %) in a single transaction. The code comment at line 745 explicitly acknowledges this: [2](#0-1) 

**Path 2 — `switch_delegation_pool` and `enter_delegation_pool` carry no commission bound.**

`switch_delegation_pool` in `src/pool/pool.cairo` validates only that `amount > 0` and `amount <= unpool_amount`. It never reads or constrains the destination pool's commission: [3](#0-2) 

`enter_delegation_pool` has the same omission: [4](#0-3) 

---

### Impact Explanation

A delegator who switches to (or enters) a pool expecting a 2 % commission ends up in a 90 % commission pool. Every subsequent epoch's rewards are split 90/10 in the staker's favour instead of 2/98. The delegator cannot exit immediately — they must wait through the full `exit_wait_window` (up to 12 weeks per `MAX_EXIT_WAIT_WINDOW`). During that window all accrued yield is silently redirected to the staker via the inflated commission. This constitutes **theft of unclaimed yield** (High impact).

---

### Likelihood Explanation

1. Any staker can call `set_commission_commitment` with an arbitrarily high `max_commission` (the only constraint is `current_commission <= max_commission`): [5](#0-4) 

2. On Starknet the sequencer orders transactions; a staker who monitors the mempool (or simply races) can insert `set_commission(max_commission)` before the delegator's `switch_delegation_pool` or `enter_delegation_pool`.
3. The attack requires no privileged role — any registered staker with an active commitment can execute it against any delegator.

---

### Recommendation

Add a caller-supplied `max_commission` guard to both entry points:

```cairo
fn switch_delegation_pool(
    ref self: ContractState,
    to_staker: ContractAddress,
    to_pool: ContractAddress,
    amount: Amount,
    max_commission: Commission,   // <-- new parameter
) -> Amount {
    // existing checks …
    let actual_commission = IStakingDispatcher { contract_address: … }
        .staker_pool_info(staker_address: to_staker)
        .commission
        .unwrap();
    assert!(actual_commission <= max_commission, "COMMISSION_EXCEEDS_SLIPPAGE");
    // …
}
```

Apply the same guard to `enter_delegation_pool`. This mirrors the slippage-tolerance pattern recommended in the external report.

---

### Proof of Concept

```
1. Staker deploys with commission = 200 (2 %).
2. Staker calls set_commission_commitment(max_commission: 9000, expiration_epoch: current + 100).
3. Delegator calls exit_delegation_pool_intent(amount) on their current pool,
   intending to switch to the staker's pool.
4. Staker observes the pending switch_delegation_pool transaction and front-runs it:
       set_commission(commission: 9000)   // jumps from 2 % → 90 %
5. Delegator's switch_delegation_pool executes; they are now a member of a 90 % commission pool.
6. For every epoch until the delegator can exit (up to 12 weeks), 90 % of their
   share of pool rewards flows to the staker instead of to the delegator.
```

Relevant code confirming no commission check exists in the switch path: [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L745-747)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
        /// **Note**: Updating epoch info can impact the commission commitment expiration date.
```

**File:** src/staking/staking.cairo (L748-780)
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
```

**File:** src/staking/staking.cairo (L1591-1597)
```text
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
