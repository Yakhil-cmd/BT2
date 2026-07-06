### Title
Delegator Can Bypass Exit Wait Window via Stale Staker `unstake_time` in `compute_unpool_time` — (File: src/staking/objects.cairo)

---

### Summary

When a staker has called `unstake_intent()` and the exit wait window has already elapsed (but `unstake_action()` has not yet been called), a delegator can call `exit_delegation_pool_intent()` and receive an `unpool_time` equal to `Time::now()`. This allows the delegator to call `exit_delegation_pool_action()` in the same block, completely bypassing the exit wait window that is supposed to apply to all delegators.

---

### Finding Description

The root cause is in `compute_unpool_time` in `src/staking/objects.cairo`:

```rust
fn compute_unpool_time(
    self: @InternalStakerInfoLatest, exit_wait_window: TimeDelta,
) -> Timestamp {
    if let Option::Some(unstake_time) = *self.unstake_time {
        return max(unstake_time, Time::now());   // ← returns now when unstake_time is in the past
    }
    Time::now().add(delta: exit_wait_window)
}
``` [1](#0-0) 

This function is called from `update_undelegate_intent_value` in `staking.cairo` every time a delegator's exit intent is registered or updated:

```rust
let unpool_time = staker_info
    .compute_unpool_time(exit_wait_window: self.exit_wait_window.read());
``` [2](#0-1) 

The intent is that when a staker is already in the exit process, the delegator's `unpool_time` is aligned with the staker's `unstake_time` (so both can exit together). However, once the staker's `unstake_time` is in the past — i.e., the staker's exit window has elapsed but `unstake_action()` has not yet been called — `max(past_unstake_time, now)` evaluates to `now`. The delegator's `unpool_time` is therefore set to the current timestamp.

The pool contract's `exit_delegation_pool_action` then checks:

```rust
assert!(Time::now() >= unpool_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);
``` [3](#0-2) 

Since `unpool_time == now`, this assertion passes immediately, and the delegator receives their funds back without waiting.

The staker is still considered "active" (i.e., `staker_removed == false`) until `unstake_action()` is called, so the pool contract's `undelegate_from_staking_contract_intent` takes the active-staker path and calls `remove_from_delegation_pool_intent` on the staking contract — which is where `compute_unpool_time` is invoked: [4](#0-3) 

---

### Impact Explanation

The exit wait window is a core protocol security mechanism. It is supposed to apply uniformly to all delegators regardless of the staker's state. By timing `exit_delegation_pool_intent()` to occur after the staker's exit window has elapsed, any delegator can reduce their own mandatory waiting period to zero. This undermines the protocol's stability guarantee and, if slashing is introduced in a future upgrade, would allow delegators to front-run slashing events and exit penalty-free. This constitutes **damage to the protocol** (Medium: griefing/damage to protocol with no direct fund theft in the current codebase).

---

### Likelihood Explanation

The precondition is simply that a staker has called `unstake_intent()` and the exit wait window has elapsed without `unstake_action()` being called. This is a routine, expected state: stakers regularly signal exit intent, and there is no on-chain enforcement requiring `unstake_action()` to be called promptly. Any delegator watching on-chain state can trivially detect this window and exploit it.

---

### Recommendation

In `compute_unpool_time`, when the staker's `unstake_time` is already in the past, the delegator should still be required to wait a full `exit_wait_window` from the current time. Replace:

```rust
return max(unstake_time, Time::now());
```

with:

```rust
return max(unstake_time, Time::now().add(delta: exit_wait_window));
```

This ensures the delegator always waits at least `exit_wait_window` from the moment they call `exit_delegation_pool_intent()`, regardless of the staker's exit window status. [5](#0-4) 

---

### Proof of Concept

1. Staker calls `unstake_intent()` at time `T`. Their `unstake_time` is set to `T + exit_wait_window`.
2. Time advances past `T + exit_wait_window`. The staker has not yet called `unstake_action()`, so `staker_removed == false`.
3. Delegator calls `exit_delegation_pool_intent(amount)` on the pool contract.
4. Pool contract calls `undelegate_from_staking_contract_intent` → `remove_from_delegation_pool_intent` on the staking contract.
5. `update_undelegate_intent_value` calls `compute_unpool_time` with `staker_info.unstake_time = Some(T + exit_wait_window)`.
6. `compute_unpool_time` returns `max(T + exit_wait_window, now) = now` (since `T + exit_wait_window < now`).
7. `unpool_time` is stored as `now`.
8. Delegator immediately calls `exit_delegation_pool_action(pool_member)`.
9. The check `Time::now() >= unpool_time` passes (`now >= now`).
10. Delegator receives their full principal back with zero waiting time, bypassing the exit wait window entirely. [6](#0-5) [7](#0-6)

### Citations

**File:** src/staking/objects.cairo (L631-638)
```text
    fn compute_unpool_time(
        self: @InternalStakerInfoLatest, exit_wait_window: TimeDelta,
    ) -> Timestamp {
        if let Option::Some(unstake_time) = *self.unstake_time {
            return max(unstake_time, Time::now());
        }
        Time::now().add(delta: exit_wait_window)
    }
```

**File:** src/staking/staking.cairo (L1831-1848)
```text
        /// Updates undelegate intent value with the given `new_intent_amount` and an updated unpool
        /// time.
        fn update_undelegate_intent_value(
            ref self: ContractState,
            token_address: ContractAddress,
            staker_info: InternalStakerInfoLatest,
            undelegate_intent_key: UndelegateIntentKey,
            new_intent_amount: NormalizedAmount,
        ) {
            let undelegate_intent_value = if new_intent_amount.is_zero() {
                Zero::zero()
            } else {
                let unpool_time = staker_info
                    .compute_unpool_time(exit_wait_window: self.exit_wait_window.read());
                assert!(token_address.is_non_zero(), "{}", InternalError::TOKEN_IS_ZERO_ADDRESS);
                UndelegateIntentValue { amount: new_intent_amount, unpool_time, token_address }
            };
            self.pool_exit_intents.write(undelegate_intent_key, undelegate_intent_value);
```

**File:** src/pool/pool.cairo (L295-330)
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
