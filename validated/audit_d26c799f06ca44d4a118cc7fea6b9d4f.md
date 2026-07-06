### Title
Permissionless `exit_delegation_pool_action` Enables Griefing of Pool Members Attempting to Switch Pools - (File: src/pool/pool.cairo)

### Summary
`exit_delegation_pool_action` in `pool.cairo` has no caller access control: any address can trigger a pool member's exit. An attacker who observes a pool member's pending `switch_delegation_pool` intent can front-run it by calling `exit_delegation_pool_action(pool_member)`, which clears the member's `unpool_time` and `unpool_amount` and sends funds back to the member. This invalidates the precondition required by `switch_delegation_pool`, forcing the member to re-enter the target pool and serve a full new `exit_wait_window` (default: 1 week) before they can exit again.

---

### Finding Description

`exit_delegation_pool_action` accepts an arbitrary `pool_member` address and performs no check that `get_caller_address() == pool_member`:

```cairo
// src/pool/pool.cairo  line 295
fn exit_delegation_pool_action(
    ref self: ContractState, pool_member: ContractAddress,
) -> Amount {
    let mut pool_member_info = self.internal_pool_member_info(:pool_member);
    let unpool_time = pool_member_info
        .unpool_time
        .expect_with_err(GenericError::MISSING_UNDELEGATE_INTENT);
    assert!(Time::now() >= unpool_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);
    ...
    pool_member_info.unpool_amount = Zero::zero();
    pool_member_info.unpool_time = Option::None;          // ← state cleared for anyone
    self.write_pool_member_info(:pool_member, :pool_member_info);
    token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());
``` [1](#0-0) 

`switch_delegation_pool`, the function the member intended to call, hard-requires `unpool_time.is_some()`:

```cairo
// src/pool/pool.cairo  line 379
fn switch_delegation_pool(...) -> Amount {
    ...
    assert!(
        pool_member_info.unpool_time.is_some(),
        "{}",
        GenericError::MISSING_UNDELEGATE_INTENT,
    );
``` [2](#0-1) 

Once `exit_delegation_pool_action` has been called by the attacker, `unpool_time` is `None`, so every subsequent `switch_delegation_pool` call by the legitimate member reverts with `MISSING_UNDELEGATE_INTENT`.

---

### Impact Explanation

The pool member:
- Cannot execute the atomic pool-switch they intended.
- Must call `enter_delegation_pool` on the target pool from scratch.
- Must serve a full new `exit_wait_window` (default 1 week, max 12 weeks) before they can exit the new pool.

During that forced re-lock period the member cannot exit the new pool, constituting **temporary freezing of funds** and potential **loss of unclaimed yield** (they miss the window to switch to a lower-commission pool without delay). This matches the allowed impact: *Temporary freezing of funds* / *Griefing with no profit motive but damage to users or protocol*.

---

### Likelihood Explanation

- The attack requires no special privilege: any EOA or contract can call `exit_delegation_pool_action(victim)` once `Time::now() >= unpool_time`.
- The attacker only needs to monitor the mempool (or on-chain state) for pool members who have set an exit intent and are likely to call `switch_delegation_pool`.
- The cost is a single transaction; the attacker loses nothing and the victim is forced into a new lock-up period.
- The `exit_wait_window` is public state, so the exact block at which the attack becomes executable is predictable.

---

### Recommendation

Restrict `exit_delegation_pool_action` so that only the pool member (or their registered `reward_address`) can trigger it:

```cairo
fn exit_delegation_pool_action(
    ref self: ContractState, pool_member: ContractAddress,
) -> Amount {
    let caller = get_caller_address();
    let pool_member_info = self.internal_pool_member_info(:pool_member);
    assert!(
        caller == pool_member || caller == pool_member_info.reward_address,
        "{}",
        Error::CALLER_CANNOT_EXIT_POOL,
    );
    ...
```

This mirrors the access-control pattern already applied to `add_to_delegation_pool` and `claim_rewards` in the same contract. [3](#0-2) 

---

### Proof of Concept

1. **Setup**: Pool member `Alice` calls `exit_delegation_pool_intent(amount=100)`. The pool contract records `unpool_time = now + exit_wait_window` and `unpool_amount = 100`.
2. **Alice's plan**: After `unpool_time` passes, Alice intends to call `switch_delegation_pool(to_staker=B, to_pool=P2, amount=100)` to move to a lower-commission pool atomically.
3. **Attack**: Attacker `Eve` observes Alice's intent on-chain. The moment `Time::now() >= unpool_time`, Eve calls `exit_delegation_pool_action(pool_member=Alice)`.
4. **Effect**: The pool contract clears `Alice.unpool_time = None` and `Alice.unpool_amount = 0`, then transfers 100 tokens to Alice.
5. **Alice's call reverts**: Alice calls `switch_delegation_pool(...)`. The assertion `pool_member_info.unpool_time.is_some()` fails → revert with `MISSING_UNDELEGATE_INTENT`.
6. **Forced re-lock**: Alice must call `enter_delegation_pool` on P2 and wait a full new `exit_wait_window` before she can exit P2, losing the atomic switch benefit and being temporarily locked in the new pool. [4](#0-3) [1](#0-0) [5](#0-4)

### Citations

**File:** src/pool/pool.cairo (L221-232)
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
