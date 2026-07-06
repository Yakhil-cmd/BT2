### Title
No Maximum-Commission Guard in `switch_delegation_pool` and `enter_delegation_pool` Allows Staker to Drain Delegator Yield - (File: src/pool/pool.cairo)

### Summary
`switch_delegation_pool` and `enter_delegation_pool` accept no `max_commission` parameter. A staker who holds an active `CommissionCommitment` can raise their commission to any value up to `max_commission` (including 100 %) between the moment a delegator decides to join or switch and the moment that transaction is included. The delegator's funds land in a pool whose commission is now far higher than expected, permanently redirecting all future yield to the staker.

### Finding Description
`update_commission` in `staking.cairo` enforces two distinct rule-sets:

- **Without a commitment**: commission may only decrease (`commission < old_commission`).
- **With an active `CommissionCommitment`**: commission may be set to *any* value that satisfies `commission <= max_commission` and `commission != old_commission` — including a large increase. [1](#0-0) 

A staker can therefore pre-arm themselves by calling `set_commission_commitment(max_commission: 10000, expiration_epoch: ...)`, which places no restriction on the current commission and is entirely permissionless for any staker.

Neither `enter_delegation_pool` nor `switch_delegation_pool` in the pool contract reads or validates the current commission of the pool being joined: [2](#0-1) [3](#0-2) 

There is no `max_commission` parameter in either function signature, so the delegator has no on-chain way to bound the commission they will actually receive.

### Impact Explanation
Once the delegator's funds are in the pool, the staker's commission applies to every future reward distribution via `update_rewards_from_staking_contract`. At 100 % commission the delegator receives zero yield indefinitely. The delegator's principal is not at risk (they can exit after the wait window), but all accrued yield from the moment of entry until exit is stolen. This maps to **High – Theft of unclaimed yield**. [4](#0-3) 

### Likelihood Explanation
Low-to-Medium. The preconditions are:

1. The staker must have called `set_commission_commitment` with a high `max_commission` before the delegator's transaction. This is a public, permissionless call any staker can make.
2. The staker must submit a `set_commission` increase in the same block or just before the delegator's transaction. On Starknet the sequencer controls ordering, so a malicious staker who also controls (or bribes) the sequencer can guarantee ordering; even without sequencer collusion, natural transaction races make this possible.
3. The victim must be calling `switch_delegation_pool` or `enter_delegation_pool` — both are common delegator actions.

The attack is fully reachable by an unprivileged staker with no external dependencies.

### Recommendation
Add a `max_commission: Commission` parameter to both `enter_delegation_pool` and `switch_delegation_pool`. At the start of each function, read the current commission from the staking contract and assert it does not exceed the caller-supplied bound:

```cairo
fn enter_delegation_pool(
    ref self: ContractState,
    reward_address: ContractAddress,
    amount: Amount,
    max_commission: Commission,   // <-- new
) {
    let current_commission = self.get_commission_from_staking_contract();
    assert!(current_commission <= max_commission, "commission exceeds max");
    // ... rest of logic unchanged
}
```

Apply the same guard to `switch_delegation_pool` and `add_to_delegation_pool`.

### Proof of Concept

```
1. Staker deploys pool, sets commission = 500 (5 %).
2. Staker calls set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 50).
   → Commitment is now active; staker may raise commission to any value ≤ 10000.

3. Delegator observes 5 % commission and submits:
     pool.exit_delegation_pool_intent(amount)   // on old pool
   then prepares:
     pool_A.switch_delegation_pool(to_staker, to_pool_A, amount)

4. Before the delegator's switch tx is included, staker submits:
     staking.set_commission(commission: 10000)  // 100 %
   This succeeds because an active commitment with max_commission=10000 exists.
   (src/staking/staking.cairo lines 1583-1589)

5. Delegator's switch_delegation_pool tx is included next.
   No commission check is performed inside switch_delegation_pool.
   (src/pool/pool.cairo lines 379-429)
   Funds land in pool_A which now has 100 % commission.

6. Every subsequent reward epoch: split_rewards_with_commission gives 100 % to the
   staker and 0 % to the pool → delegator earns zero yield until they exit.
```

### Citations

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
