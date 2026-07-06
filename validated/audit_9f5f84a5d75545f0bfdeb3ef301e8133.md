### Title
Missing Commission Slippage Protection in `switch_delegation_pool` and `enter_delegation_pool` — (File: src/pool/pool.cairo)

---

### Summary

`switch_delegation_pool`, `enter_delegation_pool`, and `add_to_delegation_pool` in `pool.cairo` accept no `max_commission` parameter. The commission applied to a delegator's future yield is inferred entirely from the destination staker's current on-chain state at execution time. Because `set_commission` in `staking.cairo` permits a staker with an active `CommissionCommitment` to **increase** commission up to `max_commission` at any time, a staker can front-run a delegator's transaction and silently redirect a large fraction of that delegator's yield to themselves.

---

### Finding Description

**Root cause — commission can be increased when a commitment is active**

`update_commission` in `staking.cairo` enforces different rules depending on whether a `CommissionCommitment` is active: [1](#0-0) 

Without a commitment, commission can only decrease. With an **active** commitment, commission may be set to any value `<= max_commission`, including a large increase. The commitment itself is set by the staker via `set_commission_commitment`, which only requires `current_commission <= max_commission`: [2](#0-1) 

**Root cause — no slippage guard in delegation entry points**

`enter_delegation_pool` accepts only `reward_address` and `amount`; no `max_commission` is checked: [3](#0-2) 

`add_to_delegation_pool` similarly accepts only `pool_member` and `amount`: [4](#0-3) 

`switch_delegation_pool` accepts `to_staker`, `to_pool`, and `amount` — no commission bound on the destination pool: [5](#0-4) 

The commission of the destination pool is never read or validated inside any of these three functions. It is applied silently at reward-distribution time.

---

### Impact Explanation

**High — Theft of unclaimed yield.**

A staker with `max_commission = 9900` (99 %) in their active commitment can jump from 1 % to 99 % in a single `set_commission` call. Every delegator who joins or switches to that pool after the increase — or whose join/switch transaction is executed after the front-run — will have 99 % of their earned rewards taken as commission. The delegator has no on-chain mechanism to detect or reject this before their funds are committed.

---

### Likelihood Explanation

**Medium.**

The precondition is that the staker has previously called `set_commission_commitment` with a high `max_commission`. This is a public, permissionless action any staker can take. Starknet's sequencer ordering is observable, so a staker can detect a pending `enter_delegation_pool` or `switch_delegation_pool` transaction and insert a `set_commission` call ahead of it. The attack requires no privileged role, no key compromise, and no external dependency — only a staker who has set up a commitment in advance.

---

### Recommendation

1. Add a `max_commission: Commission` parameter to `enter_delegation_pool`, `add_to_delegation_pool`, and `switch_delegation_pool`.
2. Inside each function, read the staker's current commission from the staking contract and assert `current_commission <= max_commission` before transferring funds or recording the delegation.
3. Optionally add a `deadline: Timestamp` parameter and assert `Time::now() <= deadline` to bound how long a submitted transaction remains valid.

---

### Proof of Concept

1. Staker S deploys a pool and calls `set_commission(commission: 100)` (1 %).
2. Staker S calls `set_commission_commitment(max_commission: 9900, expiration_epoch: current + 52)` — commits to allow up to 99 % for one year.
3. Delegator D observes 1 % commission and submits `enter_delegation_pool(reward_address: D_reward, amount: 1_000_000_STRK)`.
4. Staker S observes D's pending transaction in the mempool and submits `set_commission(commission: 9900)` with higher priority (or simply in the same block before D's tx).
5. D's `enter_delegation_pool` executes with the pool now at 99 % commission. No assertion fails; the call succeeds.
6. At every subsequent reward epoch, 99 % of D's delegation rewards flow to S as commission. D receives only 1 % of what they expected.

The same attack applies to `switch_delegation_pool`: a delegator switching to what they believe is a low-commission pool can be front-run identically, with the added disadvantage that their funds are already in an exit-intent state and they cannot easily reverse course. [6](#0-5) [7](#0-6)

### Citations

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

**File:** src/pool/pool.cairo (L221-239)
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
