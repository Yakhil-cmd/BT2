### Title
Unrestricted `exit_delegation_pool_action` Allows Anyone to Force Pool Member Exit, Blocking Pool Switching - (File: src/pool/pool.cairo)

---

### Summary

`exit_delegation_pool_action` in `src/pool/pool.cairo` accepts an arbitrary `pool_member` address and performs no caller authorization check. Any unprivileged account can invoke it for any pool member whose exit window has elapsed, forcibly completing their exit and clearing the `unpool_time`/`unpool_amount` state. This permanently blocks the victim from calling `switch_delegation_pool` (which requires `unpool_time.is_some()`), forcing them to re-enter the pool and wait another full exit window.

---

### Finding Description

`exit_delegation_pool_action` is a public `#[abi(embed_v0)]` function that takes a caller-supplied `pool_member: ContractAddress` parameter:

```cairo
fn exit_delegation_pool_action(
    ref self: ContractState, pool_member: ContractAddress,
) -> Amount {
    let mut pool_member_info = self.internal_pool_member_info(:pool_member);
    let unpool_time = pool_member_info
        .unpool_time
        .expect_with_err(GenericError::MISSING_UNDELEGATE_INTENT);
    assert!(Time::now() >= unpool_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);
    // ... no caller check ...
    pool_member_info.unpool_amount = Zero::zero();
    pool_member_info.unpool_time = Option::None;
    self.write_pool_member_info(:pool_member, :pool_member_info);
    token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());
    unpool_amount
}
``` [1](#0-0) 

There is no `assert!(get_caller_address() == pool_member || ...)` guard anywhere in this function. Contrast this with every other sensitive pool function:

- `exit_delegation_pool_intent` derives `pool_member` from `get_caller_address()` — only the member can call it. [2](#0-1) 
- `claim_rewards` explicitly asserts `caller_address == pool_member || caller_address == reward_address`. [3](#0-2) 
- `add_to_delegation_pool` asserts `caller_address == pool_member || caller_address == pool_member_info.reward_address`. [4](#0-3) 

The interface documentation for `exit_delegation_pool_action` lists no "Access control" section, unlike the other functions above. [5](#0-4) 

The critical state mutation is that after the forced call, `unpool_time` is set to `Option::None` and `unpool_amount` to zero. `switch_delegation_pool` requires `pool_member_info.unpool_time.is_some()`:

```cairo
assert!(
    pool_member_info.unpool_time.is_some(),
    "{}",
    GenericError::MISSING_UNDELEGATE_INTENT,
);
``` [6](#0-5) 

Once `exit_delegation_pool_action` is forced, this assertion will always fail for the victim, permanently blocking pool switching until they re-enter and re-signal intent.

---

### Impact Explanation

**Medium — Griefing with no profit motive but damage to users or protocol.**

A pool member who calls `exit_delegation_pool_intent` with the intent to atomically switch to a better-performing staker's pool via `switch_delegation_pool` can be front-run by any attacker calling `exit_delegation_pool_action(victim)` the moment the exit window elapses. The victim:

1. Receives their principal back (no direct theft), but loses the ability to switch pools atomically.
2. Must re-enter the target pool via `enter_delegation_pool`, paying gas again.
3. Must wait another full `DEFAULT_EXIT_WAIT_WINDOW` (1 week) before they can switch again.
4. Misses rewards from the target pool during the forced re-entry delay.

The staking contract's `unstake_action` has the same missing caller check pattern (takes `staker_address: ContractAddress` with no authorization), but its impact is lower since a staker who called `unstake_intent` is already committed to exiting. [7](#0-6) 

---

### Likelihood Explanation

**High.** The entry path requires no privilege: any externally-owned account can call `exit_delegation_pool_action(victim_address)` on any pool contract once `Time::now() >= unpool_time`. The attacker only needs to monitor the chain for `PoolMemberExitIntent` events and wait for the exit window to elapse. The attack is cheap (single transaction), repeatable, and requires no capital.

---

### Recommendation

Add a caller authorization check to `exit_delegation_pool_action`, consistent with the pattern used in `claim_rewards` and `add_to_delegation_pool`:

```cairo
fn exit_delegation_pool_action(
    ref self: ContractState, pool_member: ContractAddress,
) -> Amount {
    let pool_member_info = self.internal_pool_member_info(:pool_member);
    let caller_address = get_caller_address();
    assert!(
        caller_address == pool_member || caller_address == pool_member_info.reward_address,
        "{}",
        Error::CALLER_CANNOT_EXIT_POOL,
    );
    // ... rest of function
}
```

Apply the same fix to `unstake_action` in `src/staking/staking.cairo` (restrict to `staker_address` or their `reward_address`).

---

### Proof of Concept

1. Alice (pool member) calls `exit_delegation_pool_intent(amount)` on Pool A, intending to switch to Pool B via `switch_delegation_pool`.
2. The `DEFAULT_EXIT_WAIT_WINDOW` (1 week) elapses. Alice's `unpool_time` is now in the past.
3. Bob (attacker, any address) calls `exit_delegation_pool_action(alice_address)` on Pool A.
   - No authorization check is performed. [1](#0-0) 
   - Alice's `unpool_amount` is zeroed and `unpool_time` is set to `None`.
   - Alice's principal is transferred to her address.
4. Alice attempts to call `switch_delegation_pool(to_staker, pool_b, amount)`.
   - The assertion `pool_member_info.unpool_time.is_some()` fails. [6](#0-5) 
   - The transaction reverts with `MISSING_UNDELEGATE_INTENT`.
5. Alice must call `enter_delegation_pool` on Pool B, pay gas, and wait another full exit window before she can switch again — all caused by Bob's zero-cost griefing transaction.

### Citations

**File:** src/pool/pool.cairo (L227-232)
```text
            let caller_address = get_caller_address();
            assert!(
                caller_address == pool_member || caller_address == pool_member_info.reward_address,
                "{}",
                Error::CALLER_CANNOT_ADD_TO_POOL,
            );
```

**File:** src/pool/pool.cairo (L256-258)
```text
        fn exit_delegation_pool_intent(ref self: ContractState, amount: Amount) {
            // Asserts.
            let pool_member = get_caller_address();
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

**File:** src/pool/pool.cairo (L338-344)
```text
            let caller_address = get_caller_address();
            let reward_address = pool_member_info.reward_address;
            assert!(
                caller_address == pool_member || caller_address == reward_address,
                "{}",
                Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );
```

**File:** src/pool/pool.cairo (L389-393)
```text
            assert!(
                pool_member_info.unpool_time.is_some(),
                "{}",
                GenericError::MISSING_UNDELEGATE_INTENT,
            );
```

**File:** src/pool/interface.cairo (L87-106)
```text
    /// passed.
    /// Sends the withdrawn funds to `pool_member` and returns the transferred amount.
    ///
    /// #### Preconditions:
    /// - `pool_member` exists and requested to exit.
    /// - The exit window for `pool_member` has elapsed.
    ///
    /// #### Emits:
    /// - [`PoolMemberExitAction`](Events::PoolMemberExitAction)
    ///
    /// #### Errors:
    /// - [`POOL_MEMBER_DOES_NOT_EXIST`](staking::pool::errors::Error::POOL_MEMBER_DOES_NOT_EXIST)
    /// - [`MISSING_UNDELEGATE_INTENT`](staking::errors::GenericError::MISSING_UNDELEGATE_INTENT)
    /// - [`INTENT_WINDOW_NOT_FINISHED`](staking::errors::GenericError::INTENT_WINDOW_NOT_FINISHED)
    ///
    /// #### Internal calls:
    /// - [`staking::staking::interface::IStakingPool::remove_from_delegation_pool_action`]
    fn exit_delegation_pool_action(
        ref self: TContractState, pool_member: ContractAddress,
    ) -> Amount;
```

**File:** src/staking/staking.cairo (L483-490)
```text
        fn unstake_action(ref self: ContractState, staker_address: ContractAddress) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let unstake_time = staker_info
                .unstake_time
                .expect_with_err(Error::MISSING_UNSTAKE_INTENT);
            assert!(Time::now() >= unstake_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);
```
