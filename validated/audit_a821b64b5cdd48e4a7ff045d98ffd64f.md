### Title
Pool Member's Remaining Balance Temporarily Frozen After Staker Removal When Partial Exit Intent Is Active - (File: src/pool/pool.cairo)

### Summary

When a pool member has an active partial exit intent (`unpool_time.is_some()`) and the associated staker is subsequently removed via `unstake_action`, the pool member's remaining delegated balance (the non-unpool portion, which is transferred to the pool contract during staker removal) becomes temporarily inaccessible. Any attempt to call `exit_delegation_pool_intent` reverts with `UNDELEGATE_IN_PROGRESS`, mirroring the external report's pattern of a state flag blocking a legitimate withdrawal path.

---

### Finding Description

The `staker_removed` boolean in `pool.cairo` is the direct analog of the `emergencyWithdraw` flag in the external report. When the staker exits via `unstake_action`, the staking contract calls `pool.set_staker_removed()` and transfers the pool's delegated balance (the non-unpool portion) to the pool contract. [1](#0-0) 

After this, `staker_removed = true`. The pool member's remaining balance now sits inside the pool contract. To withdraw it, the pool member must call `exit_delegation_pool_intent` again. However, `exit_delegation_pool_intent` internally calls `undelegate_from_staking_contract_intent`: [2](#0-1) 

The guard at line 640–655 checks: if `staker_removed == true` **and** `unpool_time.is_some()`, it panics with `UNDELEGATE_IN_PROGRESS`. This blocks the pool member from initiating any new intent — including one for the remaining balance that is already sitting in the pool contract and requires no interaction with the staking contract at all.

The pool member is also blocked from:
- Calling `exit_delegation_pool_intent(0)` to cancel the existing intent (same guard fires).
- Using `switch_delegation_pool` for the remaining balance (it only moves `unpool_amount`, not the remaining delegated balance). [3](#0-2) 

The only escape path is to wait for the original `unpool_time` to elapse, call `exit_delegation_pool_action` to drain the `unpool_amount`, and only then call `exit_delegation_pool_intent` again for the remaining balance (which now succeeds because `unpool_time` is `None`). [4](#0-3) 

---

### Impact Explanation

A pool member's principal (not just yield) is temporarily frozen in the pool contract for up to `MAX_EXIT_WAIT_WINDOW` (12 weeks). [5](#0-4) 

The frozen amount is the non-unpool portion of the pool member's balance. This matches the allowed impact: **Temporary freezing of funds**.

---

### Likelihood Explanation

The scenario requires two sequential, ordinary user actions:
1. A pool member calls `exit_delegation_pool_intent` with a **partial** amount (leaving some balance in the pool).
2. The staker subsequently calls `unstake_intent` + `unstake_action`.

Both are normal, permissionless operations. No privileged role, leaked key, or external dependency is required. The pool member is an unprivileged actor and the staker exit is a standard protocol flow. Likelihood is **medium**.

---

### Recommendation

In `undelegate_from_staking_contract_intent`, when `staker_removed == true`, allow a new intent even if `unpool_time.is_some()`, provided the new intent targets only the remaining delegated balance (which is already in the pool contract). Alternatively, add a dedicated `withdraw_remaining_balance` function that allows a pool member to withdraw their non-unpool balance directly from the pool contract when `staker_removed == true`, bypassing the staking contract entirely.

---

### Proof of Concept

**Setup:**
- Pool member `M` has `100` tokens delegated.
- `M` calls `exit_delegation_pool_intent(60)`:
  - `unpool_amount = 60`, `unpool_time = T` (future timestamp).
  - Remaining delegated balance in staking contract: `40`.

**Trigger:**
- Staker calls `unstake_intent()` then `unstake_action()`.
- `transfer_to_pools_when_unstake` transfers `40` tokens to the pool contract and calls `set_staker_removed()` → `staker_removed = true`. [6](#0-5) [7](#0-6) 

**Freeze:**
- `M` calls `exit_delegation_pool_intent(40)` to withdraw the remaining balance.
- Inside `undelegate_from_staking_contract_intent`:
  - `!self.is_staker_active()` → `true` (staker removed).
  - `self.internal_pool_member_info(M).unpool_time.is_none()` → `false` (still set from the earlier intent).
  - **Panics with `UNDELEGATE_IN_PROGRESS`.** [8](#0-7) 

- The `40` tokens are now in the pool contract but inaccessible until `T` elapses and `M` first completes `exit_delegation_pool_action` for the `60`-token intent.
- Maximum freeze duration: up to `MAX_EXIT_WAIT_WINDOW = 12 weeks`.

### Citations

**File:** src/staking/staking.cairo (L74-75)
```text
    pub(crate) const DEFAULT_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: WEEK };
    pub(crate) const MAX_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: 12 * WEEK };
```

**File:** src/staking/staking.cairo (L1661-1682)
```text
        fn transfer_to_pools_when_unstake(
            ref self: ContractState,
            staker_address: ContractAddress,
            staker_pool_info: StoragePath<InternalStakerPoolInfoV2>,
        ) {
            for (pool_contract, token_address) in staker_pool_info.pools {
                let pool_balance = self.get_delegated_balance(:staker_address, :pool_contract);
                let token_dispatcher = IERC20Dispatcher { contract_address: token_address };
                let pool_dispatcher = IPoolDispatcher { contract_address: pool_contract };
                pool_dispatcher.set_staker_removed();
                self
                    .insert_staker_delegated_balance(
                        :staker_address, :pool_contract, delegated_balance: Zero::zero(),
                    );
                let decimals = self.get_token_decimals(:token_address);
                token_dispatcher
                    .checked_transfer(
                        recipient: pool_contract,
                        amount: pool_balance.to_native_amount(:decimals).into(),
                    );
            }
        }
```

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
