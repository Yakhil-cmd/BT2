### Title
Missing Slippage Protection in `enter_delegation_pool` and `switch_delegation_pool` Allows Commission Frontrunning - (File: src/pool/pool.cairo)

### Summary
`enter_delegation_pool` and `switch_delegation_pool` in `src/pool/pool.cairo` accept no `max_commission` parameter. A staker who holds an active commission commitment can increase their commission to `max_commission` in the same block, frontrunning a delegator's entry or pool-switch transaction. The delegator's funds are locked in at the higher commission with no recourse until the exit-wait window expires.

### Finding Description

**Root cause — commission can increase within an active commitment**

`set_commission` in `src/staking/staking.cairo` enforces two distinct code paths: [1](#0-0) 

Without a commitment, commission can only decrease. With an *active* commitment, the staker may set any value `<= max_commission` and `!= old_commission`. Because `set_commission_commitment` only requires `current_commission <= max_commission`: [2](#0-1) 

a staker can legitimately set `max_commission = 50 %` while charging `5 %` today, then atomically raise to `50 %` at any moment. The code itself carries a warning about this: [3](#0-2) 

**Vulnerable entry points — no `max_commission` guard**

`enter_delegation_pool` transfers the delegator's tokens and creates the pool-member record with no check on the current commission: [4](#0-3) 

`switch_delegation_pool` moves an existing delegator to a new pool, again with no commission bound: [5](#0-4) 

### Impact Explanation

A delegator who enters or switches to a pool at `5 %` commission but is frontrun into a `50 %` commission pool loses `45 %` of all future yield until they complete the full exit-wait-window cycle. This is a direct, ongoing theft of unclaimed yield from an unprivileged user, matching the **High: Theft of unclaimed yield** impact category.

### Likelihood Explanation

**Low.** The attack requires:
1. The staker to have set a commission commitment with `max_commission` materially above the current commission.
2. The staker (or a colluding sequencer) to observe and frontrun the delegator's pending transaction.

Starknet's sequencer is currently centralised, making transaction ordering manipulation feasible for a determined actor. The precondition (active commitment with headroom) is a normal, documented protocol feature, so it will exist in practice.

### Recommendation

Add a `max_commission` parameter to both `enter_delegation_pool` and `switch_delegation_pool`. Revert if the pool's current commission exceeds the caller's stated maximum:

```cairo
fn enter_delegation_pool(
    ref self: ContractState,
    reward_address: ContractAddress,
    amount: Amount,
    max_commission: Commission,   // 0 = no protection (opt-out)
) {
    ...
    if max_commission != 0 {
        let current_commission = self.get_commission_from_staking_contract();
        assert!(current_commission <= max_commission, Error::COMMISSION_TOO_HIGH);
    }
    ...
}
```

Apply the same guard inside `switch_delegation_pool` before calling `switch_staking_delegation_pool`.

### Proof of Concept

1. Staker deploys a STRK pool, sets commission to `5 %`, then calls `set_commission_commitment(max_commission: 5000, expiration_epoch: current + 50)` (50 % ceiling).
2. Alice observes the pool at `5 %` and submits `enter_delegation_pool(reward_addr, 1_000_000_STRK)`.
3. The staker (or sequencer) inserts `set_commission(5000)` immediately before Alice's transaction in the same block.
4. Alice's transaction executes: `get_commission_from_staking_contract()` now returns `50 %`.
5. Alice is a pool member at `50 %` commission. She must wait the full `exit_wait_window` (up to 12 weeks) to exit, losing `45 %` of all yield accrued during that period to the staker. [6](#0-5) [1](#0-0)

### Citations

**File:** src/staking/staking.cairo (L745-747)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
        /// **Note**: Updating epoch info can impact the commission commitment expiration date.
```

**File:** src/staking/staking.cairo (L769-771)
```text
            let current_commission = staker_pool_info.commission();
            assert!(current_commission <= max_commission, "{}", Error::MAX_COMMISSION_TOO_LOW);
            assert!(expiration_epoch > current_epoch, "{}", Error::EXPIRATION_EPOCH_TOO_EARLY);
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
