### Title
Pool Member `pool_member_info` Not Deleted After Full Exit, Permanently Blocking Re-Entry Into Same Pool — (`src/pool/pool.cairo`)

### Summary

After a pool member fully exits a delegation pool via `exit_delegation_pool_action()`, their `pool_member_info` storage entry is updated (zeroed) but never deleted. Because `enter_delegation_pool()` unconditionally rejects any caller whose `pool_member_info` is not `None`, a fully-exited pool member can never re-enter the same pool through the standard entry path.

### Finding Description

`exit_delegation_pool_action()` clears `unpool_amount` and `unpool_time` in the pool member's record and writes it back to storage, but it never sets the entry to `VInternalPoolMemberInfo::None`: [1](#0-0) 

After this call, `pool_member_info.read(pool_member)` returns `VInternalPoolMemberInfo::V1(...)` — not `None`.

`enter_delegation_pool()` guards re-entry with a strict `is_none()` check: [2](#0-1) 

Because the record is never deleted, this assertion always fails for any address that has previously exited, regardless of whether their current balance is zero.

By contrast, `enter_delegation_pool_from_staking_contract()` (used by `switch_delegation_pool`) explicitly handles the case where a pool member already exists: [3](#0-2) 

This asymmetry confirms the design intends to allow re-entry via switching, but the direct entry path is unintentionally blocked.

### Impact Explanation

Any pool member who performs a full exit (`exit_delegation_pool_intent(total_balance)` followed by `exit_delegation_pool_action()`) is permanently unable to call `enter_delegation_pool()` on the same pool contract again. The only workaround is to join a *different* pool, create an exit intent there, and then call `switch_delegation_pool()` targeting the original pool — a multi-step process that requires another pool to exist and be joinable. If no other pool is available for the same token, the pool member is permanently locked out of re-entering that pool.

This matches the allowed impact: **griefing with no profit motive but damage to users**.

### Likelihood Explanation

Any pool member who fully exits and later wishes to re-enter the same pool will hit this. The flow is a natural user action (exit, wait, re-enter), so the likelihood is realistic for any active delegation pool. No special privileges or external conditions are required — the pool member triggers it themselves.

### Recommendation

In `exit_delegation_pool_action()`, after transferring funds, check whether the pool member's remaining balance and `unpool_amount` are both zero. If so, delete the record by writing `VInternalPoolMemberInfo::None`:

```cairo
// After transfer, if fully exited, delete the record.
if pool_member_info.unpool_amount.is_zero()
    && self.get_last_member_balance(:pool_member).is_zero()
{
    self.pool_member_info.write(pool_member, VInternalPoolMemberInfo::None);
} else {
    self.write_pool_member_info(:pool_member, :pool_member_info);
}
```

Alternatively, modify `enter_delegation_pool()` to handle existing records with zero balance (analogous to `enter_delegation_pool_from_staking_contract()`).

### Proof of Concept

1. Pool member `A` calls `enter_delegation_pool(reward_addr, 100)` on pool `P` — succeeds, `pool_member_info[A]` is set.
2. `A` calls `exit_delegation_pool_intent(100)` — full exit intent, balance trace set to 0.
3. After the exit wait window, `A` calls `exit_delegation_pool_action(A)` — 100 tokens returned, `pool_member_info[A]` written back with `unpool_amount=0`, `unpool_time=None`, but **not deleted**.
4. `A` calls `enter_delegation_pool(reward_addr, 100)` again — **reverts with `POOL_MEMBER_EXISTS`** because `pool_member_info.read(A)` is `VInternalPoolMemberInfo::V1(...)`, not `None`. [4](#0-3) [5](#0-4)

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

**File:** src/pool/pool.cairo (L295-333)
```text
        fn exit_delegation_pool_action(
            ref self: ContractState, pool_member: ContractAddress,
        ) -> Amount {
            // Asserts.
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let unpool_time = pool_member_info
                .unpool_time
                .expect_with_err(GenericError::MISSING_UNDELEGATE_INTENT);
            assert!(Time::now() >= unpool_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);

            // Emit event.
            self
                .emit(
                    Events::PoolMemberExitAction {
                        pool_member, unpool_amount: pool_member_info.unpool_amount,
                    },
                );

            // Perform removal action in the staking contract, receiving funds if needed.
            // Note that if the intent was done after the staker was removed (unstake_action),
            // the funds will already be in the pool contract, and the following call will do
            // nothing.
            let staking_pool_dispatcher = self.staking_pool_dispatcher.read();
            staking_pool_dispatcher
                .remove_from_delegation_pool_action(identifier: pool_member.into());

            let unpool_amount = pool_member_info.unpool_amount;
            pool_member_info.unpool_amount = Zero::zero();
            pool_member_info.unpool_time = Option::None;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer delegated amount to the pool member.
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());

            unpool_amount
        }
```

**File:** src/pool/pool.cairo (L446-458)
```text
            let pool_member_info = match self.get_internal_pool_member_info(:pool_member) {
                Option::Some(pool_member_info) => {
                    // Pool member already exists. Need to update pool_member_info to account for
                    // the accrued rewards and then update the delegated amount.
                    assert!(
                        pool_member_info.reward_address == switch_pool_data.reward_address,
                        "{}",
                        Error::REWARD_ADDRESS_MISMATCH,
                    );
                    // Update the pool member's balance checkpoint.
                    self.increase_member_balance(:pool_member, :amount);
                    VInternalPoolMemberInfoTrait::wrap_latest(value: pool_member_info)
                },
```
