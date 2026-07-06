### Title
Unauthorized Caller Can Force Pool Member Exit, Blocking Pool Switch — (`src/pool/pool.cairo`)

---

### Summary

`exit_delegation_pool_action` in `src/pool/pool.cairo` accepts a `pool_member` address parameter but performs **no caller identity check**. Any unprivileged address can call it to forcibly complete another pool member's pending exit once the exit window has elapsed, permanently clearing the member's `unpool_time` and `unpool_amount` and preventing them from executing a `switch_delegation_pool` they may have been planning.

---

### Finding Description

The vulnerability class is **authorization bypass**: a state-mutating function that should be restricted to the owning pool member is callable by any address.

The intent/action pattern for pool exits works as follows:

1. Pool member calls `exit_delegation_pool_intent(amount)` — sets `unpool_time` and `unpool_amount` on their record.
2. After the exit window, the member may either:
   - Call `exit_delegation_pool_action(pool_member)` to withdraw funds, **or**
   - Call `switch_delegation_pool(to_staker, to_pool, amount)` to atomically move to a new pool (requires `unpool_time.is_some()`).

The action step is implemented as:

```cairo
fn exit_delegation_pool_action(
    ref self: ContractState, pool_member: ContractAddress,
) -> Amount {
    let mut pool_member_info = self.internal_pool_member_info(:pool_member);
    let unpool_time = pool_member_info
        .unpool_time
        .expect_with_err(GenericError::MISSING_UNDELEGATE_INTENT);
    assert!(Time::now() >= unpool_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);
    // ... no get_caller_address() check ...
    pool_member_info.unpool_amount = Zero::zero();
    pool_member_info.unpool_time = Option::None;
    self.write_pool_member_info(:pool_member, :pool_member_info);
    token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());
    unpool_amount
}
``` [1](#0-0) 

There is no `assert!(get_caller_address() == pool_member, ...)` guard. Compare this to every other pool function that touches a member's state:

- `exit_delegation_pool_intent` — interface explicitly states **"Only the pool member address"** [2](#0-1) 
- `claim_rewards` — asserts `caller_address == pool_member || caller_address == reward_address` [3](#0-2) 
- `add_to_delegation_pool` — asserts `caller_address == pool_member || caller_address == pool_member_info.reward_address` [4](#0-3) 

The interface documentation for `exit_delegation_pool_action` lists no **Access control** section at all, confirming the omission. [5](#0-4) 

`switch_delegation_pool` requires `pool_member_info.unpool_time.is_some()` to proceed:

```cairo
assert!(
    pool_member_info.unpool_time.is_some(),
    "{}",
    GenericError::MISSING_UNDELEGATE_INTENT,
);
``` [6](#0-5) 

Once an attacker calls `exit_delegation_pool_action` on the victim, `unpool_time` is cleared, and `switch_delegation_pool` will permanently revert for that pending intent.

---

### Impact Explanation

**Medium — Griefing with no profit motive but damage to users.**

- The attacker cannot steal the principal; funds are transferred to `pool_member` (the correct recipient).
- The attacker destroys the victim's ability to atomically switch delegation pools. The victim must re-enter a new pool from scratch via `enter_delegation_pool`, losing any rewards that would have accrued during the transition period and forfeiting the atomic switch guarantee.
- Unclaimed rewards are not lost (the `reward_checkpoint` and `entry_to_claim_from` fields are preserved), so this does not rise to High.

---

### Likelihood Explanation

**Medium.** The attacker only needs to:
1. Monitor on-chain `PoolMemberExitIntent` events (publicly emitted).
2. Wait for `Time::now() >= unpool_time`.
3. Front-run or race the victim's `switch_delegation_pool` call with `exit_delegation_pool_action(victim)`.

No privileged access, leaked keys, or external dependencies are required. The attack is cheap (single transaction) and repeatable against any pool member in an exit window.

---

### Recommendation

Add a caller identity check at the top of `exit_delegation_pool_action`, consistent with the pattern used by every other pool member–scoped function:

```cairo
fn exit_delegation_pool_action(
    ref self: ContractState, pool_member: ContractAddress,
) -> Amount {
    assert!(
        get_caller_address() == pool_member,
        "{}",
        Error::CALLER_IS_NOT_POOL_MEMBER,  // new error variant
    );
    // ... rest of function unchanged ...
}
``` [7](#0-6) 

---

### Proof of Concept

1. **Setup**: Pool member `Alice` calls `exit_delegation_pool_intent(amount)`. This sets `Alice.unpool_time = now + exit_window` and `Alice.unpool_amount = amount`. Alice intends to call `switch_delegation_pool(better_staker, better_pool, amount)` once the window elapses to move her stake atomically.

2. **Attack**: Attacker `Eve` monitors the chain for `PoolMemberExitIntent` events. Once `Time::now() >= Alice.unpool_time`, Eve calls `pool.exit_delegation_pool_action(Alice)` before Alice can act.

3. **Effect**: The call succeeds because there is no caller check. `Alice.unpool_amount` is cleared to zero, `Alice.unpool_time` is set to `None`, and `unpool_amount` tokens are transferred to Alice (not Eve).

4. **Consequence**: Alice's subsequent call to `switch_delegation_pool(better_staker, better_pool, amount)` reverts with `MISSING_UNDELEGATE_INTENT` because `unpool_time` is now `None`. Alice must re-enter the new pool from scratch via `enter_delegation_pool`, losing rewards accrued during the forced transition gap. Eve pays only gas.

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

**File:** src/pool/interface.cairo (L79-80)
```text
    /// #### Access control:
    /// Only the pool member address.
```

**File:** src/pool/interface.cairo (L86-106)
```text
    /// Completes a pending exit for the given pool member once the required waiting period has
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
