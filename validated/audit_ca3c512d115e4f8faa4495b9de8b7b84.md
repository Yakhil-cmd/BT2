### Title
Exit Intent Timer Always Resets on Any Amount Modification, Causing Temporary Freezing of Already-Eligible Funds - (File: src/staking/staking.cairo)

### Summary
The `update_undelegate_intent_value` function in the staking contract unconditionally resets `unpool_time` to `Time::now() + exit_wait_window` on every call to `remove_from_delegation_pool_intent`, regardless of whether the intent amount is being increased or decreased. A pool member whose 100 STRK has already cleared the exit window can have those funds re-locked for up to 12 additional weeks simply by adding 10 more STRK and re-submitting an exit intent for the combined 110 STRK — a direct analog to the "cooldown applied to entire balance" pattern in the external report.

### Finding Description
`update_undelegate_intent_value` is the internal function that writes the `UndelegateIntentValue` record for every pool-member exit intent:

```cairo
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
        ...
        UndelegateIntentValue { amount: new_intent_amount, unpool_time, token_address }
    };
    self.pool_exit_intents.write(undelegate_intent_key, undelegate_intent_value);
}
``` [1](#0-0) 

`compute_unpool_time` always returns `Time::now() + exit_wait_window` when the staker is active:

```cairo
fn compute_unpool_time(
    self: @InternalStakerInfoLatest, exit_wait_window: TimeDelta,
) -> Timestamp {
    if let Option::Some(unstake_time) = *self.unstake_time {
        return max(unstake_time, Time::now());
    }
    Time::now().add(delta: exit_wait_window)
}
``` [2](#0-1) 

The public interface explicitly documents this behaviour:

> "The function supports overriding intentions, upwards **and downwards**, *which recalculates the unpool_time and restarts the timer*." [3](#0-2) 

The call chain is: `Pool::exit_delegation_pool_intent` → `undelegate_from_staking_contract_intent` → `St

### Citations

**File:** src/staking/staking.cairo (L1833-1849)
```text
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
        }
```

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

**File:** src/staking/interface.cairo (L179-186)
```text
    /// The function supports overriding intentions, upwards and downwards, *which recalculates the
    /// unpool_time and restarts the timer*. This slightly changes the flow, meaning that if the
    /// pool already has an intent for this `identifier`, the flow remains the same except for
    /// points 2 and 3:
    /// * If the amount to be removed is greater in the previous intent, the staker's pooled amount
    ///   and total_stake will be *decreased* by the difference between the new and the old amount.
    /// * If the amount to be removed is smaller in the previous intent, the staker's pooled amount
    ///   and total_stake will be *increased* by the difference between the old and the new amount.
```
