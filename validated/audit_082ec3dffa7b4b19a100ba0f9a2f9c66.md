### Title
Pool Member's Non-Intent Balance Temporarily Frozen After Staker Removal - (File: `src/pool/pool.cairo`)

### Summary

When a pool member has a **partial** exit intent in progress and the staker subsequently completes `unstake_action`, the pool member's remaining balance (the portion not covered by the exit intent) becomes inaccessible until the original exit wait window expires. The `UNDELEGATE_IN_PROGRESS` guard in `undelegate_from_staking_contract_intent` blocks any new exit intent while the original intent is still pending, even though the remaining funds are already held in the pool contract.

### Finding Description

`undelegate_from_staking_contract_intent` in `src/pool/pool.cairo` (lines 637–663) contains a guard that fires when:
1. The staker is inactive (`staker_removed == true`), **AND**
2. The pool member already has an exit intent in progress (`unpool_time.is_some()`) [1](#0-0) 

The guard was added to prevent a state inconsistency (the staking contract's `pool_exit_intents` map cannot be updated after the staker is removed). However, it has the side effect of locking the pool member's **remaining** balance — the portion not covered by the exit intent — until the original `unpool_time` expires.

The exact sequence:

1. Pool member calls `exit_delegation_pool_intent(partial_amount)` → `unpool_time = T`, `unpool_amount = partial_amount`, remaining `balance` stays in the staking contract.
2. Staker calls `unstake_intent()` + `unstake_action()` → staker removed, `balance` is transferred to the pool contract, `set_staker_removed()` is called. [2](#0-1) [3](#0-2) 

3. Pool member tries to call `exit_delegation_pool_intent(balance)` → `undelegate_from_staking_contract_intent` sees staker inactive + `unpool_time.is_some()` → **REVERTS with `UNDELEGATE_IN_PROGRESS`**. [4](#0-3) 

4. `exit_delegation_pool_action` only transfers `unpool_amount` (the partial amount), not the remaining `balance`. [5](#0-4) 

5. The remaining `balance` sits in the pool contract with no withdrawal path until `T` passes.

After `T` passes, the pool member can call `exit_delegation_pool_action` (gets `partial_amount`), then call `exit_delegation_pool_intent(balance)` (staker inactive + `unpool_time.is_none()` → allowed, returns `Time::now()`), then immediately call `exit_delegation_pool_action` again to get `balance`. The remaining balance is locked for up to `exit_wait_window`. [6](#0-5) 

### Impact Explanation

**Temporary freezing of funds.** The pool member's remaining balance (not covered by the exit intent) is locked in the pool contract for up to `exit_wait_window` (the protocol's configured exit wait window, e.g. 21 days). The funds are not lost — they are recoverable after the original `unpool_time` expires — but they are inaccessible during that window. This matches the allowed impact: *Temporary freezing of funds*.

### Likelihood Explanation

Any pool member who has a **partial** exit intent in progress at the time the staker calls `unstake_action` is affected. This is a realistic scenario:
- Pool members routinely call partial exit intents to withdraw a portion of their stake.
- Stakers can exit at any time without coordinating with pool members.
- The staker's `unstake_action` is callable by **any address** (no access control), so the timing is not under the pool member's control. [7](#0-6) 

### Recommendation

When the staker is inactive and the pool member has an exit intent in progress, allow the pool member to call `exit_delegation_pool_intent` for their **remaining** balance (i.e., `total_amount - unpool_amount`). Since the remaining funds are already in the pool contract after `unstake_action`, no interaction with the staking contract is needed. The fix in `undelegate_from_staking_contract_intent` should permit a new intent for the non-intent portion when the staker is removed, or alternatively, `exit_delegation_pool_action` should transfer both `unpool_amount` and the remaining balance in a single call when the staker is removed.

### Proof of Concept

```
1. Pool member calls exit_delegation_pool_intent(partial_amount)
   → unpool_time = T, unpool_amount = partial_amount
   → remaining balance stays in staking contract

2. Staker calls unstake_intent() + unstake_action()
   → staker_removed = true
   → remaining balance transferred to pool contract
   → set_staker_removed() called on pool

3. Pool member calls exit_delegation_pool_intent(remaining_balance)
   → undelegate_from_staking_contract_intent:
       !is_staker_active() == true
       unpool_time.is_some() == true
       → PANIC: "Undelegate from pool in progress, pool member is in an exit window"

4. Pool member's remaining_balance is locked in pool contract until T.
   exit_delegation_pool_action only returns partial_amount.
   No other function can release remaining_balance before T.
```

### Citations

**File:** src/pool/pool.cairo (L256-293)
```text
        fn exit_delegation_pool_intent(ref self: ContractState, amount: Amount) {
            // Asserts.
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let old_delegated_stake = self.get_last_member_balance(:pool_member);
            let total_amount = old_delegated_stake + pool_member_info.unpool_amount;
            assert!(amount <= total_amount, "{}", GenericError::AMOUNT_TOO_HIGH);

            // Notify the staking contract of the removal intent.
            let unpool_time = self.undelegate_from_staking_contract_intent(:pool_member, :amount);

            // Edit the pool member to reflect the removal intent, and write to storage.
            if amount.is_zero() {
                pool_member_info.unpool_time = Option::None;
            } else {
                pool_member_info.unpool_time = Option::Some(unpool_time);
            }
            pool_member_info.unpool_amount = amount;
            let new_delegated_stake = total_amount - amount;
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Update the pool member's balance checkpoint.
            self.set_member_balance(:pool_member, amount: new_delegated_stake);

            // Emit events.
            self
                .emit(
                    Events::PoolMemberExitIntent {
                        pool_member, exit_timestamp: unpool_time, amount,
                    },
                );
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake, new_delegated_stake,
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

**File:** src/pool/pool.cairo (L496-503)
```text
        fn set_staker_removed(ref self: ContractState) {
            // Asserts.
            self.assert_caller_is_staking_contract();
            assert!(!self.staker_removed.read(), "{}", Error::STAKER_ALREADY_REMOVED);
            self.staker_removed.write(true);
            // Emit event.
            self.emit(Events::StakerRemoved { staker_address: self.staker_address.read() });
        }
```

**File:** src/pool/pool.cairo (L637-663)
```text
        fn undelegate_from_staking_contract_intent(
            self: @ContractState, pool_member: ContractAddress, amount: Amount,
        ) -> Timestamp {
            if !self.is_staker_active() {
                // Don't allow intent if an intent is already in progress and the staker is erased.
                // Avoid the following flow:
                // 1. Member intent - moves member balance from the staker's `pool_amount` to
                // `UndelegateIntentKey`.
                // 2. Staker intent.
                // 3. Staker action - transfer the `pool_amount` from the staker to the pool
                // contract.
                // 4. Member intent - here it is no longer possible to move balance between the
                // `pool_amount` and the `UndelegateIntentKey`.
                assert!(
                    self.internal_pool_member_info(:pool_member).unpool_time.is_none(),
                    "{}",
                    Error::UNDELEGATE_IN_PROGRESS,
                );
                return Time::now();
            }
            let staking_pool_dispatcher = self.staking_pool_dispatcher.read();
            let staker_address = self.staker_address.read();
            staking_pool_dispatcher
                .remove_from_delegation_pool_intent(
                    :staker_address, identifier: pool_member.into(), :amount,
                )
        }
```

**File:** src/staking/staking.cairo (L496-514)
```text
            // Update staker info to storage (it will be erased later).
            // This is done here to avoid re-entrancy.
            self.write_staker_info(:staker_address, :staker_info);

            let staker_amount = self.get_own_balance(:staker_address).to_strk_native_amount();
            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            self.remove_staker(:staker_address, :staker_info, :staker_pool_info);

            // Return stake to staker.
            token_dispatcher
                .checked_transfer(recipient: staker_address, amount: staker_amount.into());
            // Return delegated stake to pools and zero their balances.
            self
                .transfer_to_pools_when_unstake(
                    :staker_address, staker_pool_info: staker_pool_info.as_non_mut(),
                );
            // Clear staker pools.
            staker_pool_info.pools.clear();
            staker_amount
```
