### Title
Lack of Commission Slippage Protection in `switch_delegation_pool()` and `enter_delegation_pool()` — (File: src/pool/pool.cairo)

---

### Summary

Pool members have no way to specify a maximum acceptable commission when entering or switching delegation pools. A staker who holds an active `CommissionCommitment` can front-run these transactions by calling `set_commission()` to raise their commission up to `max_commission` before the pool member's transaction executes, causing the pool member to receive substantially fewer rewards than expected.

---

### Finding Description

`switch_delegation_pool()` and `enter_delegation_pool()` in `src/pool/pool.cairo` accept a target pool address and an amount, but provide no `max_commission` guard parameter. A pool member who decides to switch or enter based on an observed commission rate has no on-chain mechanism to revert if the commission changes between transaction submission and execution.

The `update_commission()` internal function in `src/staking/staking.cairo` enforces that without a `CommissionCommitment`, commission can only decrease:

```cairo
} else {
    assert!(commission < old_commission, "{}", Error::INVALID_COMMISSION);
}
```

However, when a staker has set an active `CommissionCommitment` via `set_commission_commitment()`, the constraint becomes:

```cairo
if self.is_commission_commitment_active(:commission_commitment) {
    assert!(
        commission <= commission_commitment.max_commission,
        "{}",
        Error::INVALID_COMMISSION_WITH_COMMITMENT,
    );
    assert!(commission != old_commission, "{}", Error::INVALID_SAME_COMMISSION);
}
```

This allows the staker to raise commission to any value up to `max_commission` (which can be set as high as `COMMISSION_DENOMINATOR = 10000`, i.e. 100%). The code itself acknowledges this risk with the comment at line 745–746:

> `/// **Note**: Current commission increase safeguards still allow for sudden commission changes.`

The `switch_delegation_pool()` call chain is:

1. Pool member calls `Pool::switch_delegation_pool(to_staker, to_pool, amount)` — no `max_commission` parameter.
2. Pool calls `Staking::switch_staking_delegation_pool(...)`.
3. Staking calls `to_pool.enter_delegation_pool_from_staking_contract(amount, data)`.

At no point is the commission of `to_pool` checked against any user-supplied bound. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

---

### Impact Explanation

A staker with `max_commission = 10000` (100%) in an active `CommissionCommitment` can front-run a pool member's `switch_delegation_pool()` or `enter_delegation_pool()` call by raising their commission to 100% in the same or a preceding transaction. The pool member ends up delegating to a pool where the staker captures all pool rewards and the pool member receives zero. This constitutes **theft of unclaimed yield** — a High-severity impact under the allowed scope. [5](#0-4) [6](#0-5) 

---

### Likelihood Explanation

The attack requires the staker to have previously called `set_commission_commitment()` with a high `max_commission`. This is a deliberate, on-chain, publicly visible action. However:

- A staker can set `max_commission = 10000` and `expiration_epoch = current_epoch + 1` (minimum allowed), then immediately raise commission to 100% in the same epoch.
- On Starknet the sequencer is currently centralized, so a staker can order their `set_commission()` call ahead of a pool member's pending `switch_delegation_pool()` call within the same block.
- The pool member has no on-chain recourse once the transaction is included; they must wait out the full `exit_wait_window` (up to 12 weeks) to recover their principal, during which they earn zero rewards. [7](#0-6) [8](#0-7) 

---

### Recommendation

Add a `max_commission` slippage guard to both `switch_delegation_pool()` and `enter_delegation_pool()`. Before completing the delegation, read the current commission from the staking contract and revert if it exceeds the caller-supplied bound:

```cairo
fn switch_delegation_pool(
    ref self: ContractState,
    to_staker: ContractAddress,
    to_pool: ContractAddress,
    amount: Amount,
    max_commission: Commission,   // <-- new parameter
) -> Amount {
    // ... existing checks ...
    let current_commission = self.get_commission_from_staking_contract_for(to_staker);
    assert!(current_commission <= max_commission, Error::COMMISSION_EXCEEDS_MAX);
    // ... rest of logic ...
}
```

Apply the same pattern to `enter_delegation_pool()`. [1](#0-0) [2](#0-1) 

---

### Proof of Concept

1. Staker calls `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)` — sets a commitment allowing commission up to 100%.
2. Staker's current commission is 100 (1%), visible on-chain.
3. Pool member submits `switch_delegation_pool(to_staker: staker, to_pool: pool, amount: X)` targeting this pool.
4. Staker observes the pending transaction and calls `set_commission(10000)` — raises commission to 100% — ordering it before the pool member's tx in the same block.
5. Pool member's `switch_delegation_pool` executes successfully (no commission check), landing them in a pool with 100% commission.
6. On the next reward distribution, `split_rewards_with_commission` routes all pool rewards to the staker as commission; pool member receives zero.
7. Pool member must wait the full `exit_wait_window` (default 1 week, up to 12 weeks) to recover principal, forfeiting all yield accrued during that period. [9](#0-8) [6](#0-5) [1](#0-0)

### Citations

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

**File:** src/staking/staking.cairo (L73-75)
```text
    pub const COMMISSION_DENOMINATOR: Commission = 10000;
    pub(crate) const DEFAULT_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: WEEK };
    pub(crate) const MAX_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: 12 * WEEK };
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

**File:** src/staking/staking.cairo (L1573-1600)
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
```

**File:** src/staking/staking.cairo (L1989-1993)
```text
                let (commission_rewards, pool_rewards) = split_rewards_with_commission(
                    rewards_including_commission: pool_rewards_including_commission, :commission,
                );
                total_commission_rewards += commission_rewards;
                total_pools_rewards += pool_rewards;
```
