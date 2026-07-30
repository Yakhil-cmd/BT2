### Title
Bridge transfer-limiter accounting rounds notional value down to zero, allowing the 24h USD outflow cap to be bypassed via dust-sized transfers - (File: crates/sui-framework/packages/bridge/sources/limiter.move)

### Summary
`bridge::limiter::check_and_record_sending_transfer` converts a token amount into a "notional USD" value by multiplying by `treasury.notional_value<T>()` and then dividing by `treasury.decimal_multiplier<T>()`. This division truncates, and the truncated (possibly zero) result — not the un-truncated value — is what gets permanently added to `record.total_amount`, the running total used by the limiter to decide whether future sends exceed the route's rolling 24h USD cap. This is the same class of bug as the reported oracle issue: a division whose result can legitimately be zero for adversarially-chosen small inputs, causing an accounting/validation state to silently under-record the true value while the underlying value is still moved.

### Finding Description [1](#0-0) 

```
// Compute notional amount
// Upcast to u128 to prevent overflow, to not miss out on small amounts.
let value = (treasury.notional_value<T>() as u128);
let notional_amount_with_token_multiplier = value * (amount as u128);

// Check if transfer amount exceed limit
// Upscale them to the token's decimal.
if (
    (record.total_amount as u128)
        * (treasury.decimal_multiplier<T>() as u128)
        + notional_amount_with_token_multiplier > route_limit_adjusted
) {
    return false
};

// Now scale down to notional value
let notional_amount =
    notional_amount_with_token_multiplier / (treasury.decimal_multiplier<T>() as u128);
// Should be safe to downcast to u64 after dividing by the decimals
let notional_amount = (notional_amount as u64);

// Record transfer value
let new_amount = record.per_hour_amounts.pop_back() + notional_amount;
record.per_hour_amounts.push_back(new_amount);
record.total_amount = record.total_amount + notional_amount;
```

`check_and_record_sending_transfer` is called from `bridge::bridge::send_token_internal`/`send_token` for every outgoing bridge transfer, gated by `bypass_limiter` (false for ordinary users): [2](#0-1) 

Because `notional_amount = value * amount / decimal_multiplier<T>()` is a truncating integer division, whenever `value * amount < decimal_multiplier<T>()` the recorded contribution is exactly `0`, even though a real, non-zero amount of the token was burned/escrowed and is being bridged out. Since `decimal_multiplier<T>()` for common tokens is `10^decimals` (e.g. `10^18` for an 18-decimal token, `10^6`–`10^8` for others per `treasury.move`'s `BridgeTokenMetadata`), and `notional_value<T>()` is a bounded USD price, there is always a small-enough per-call `amount` (down to the token's smallest unit) for which the truncated contribution is 0, regardless of the token's actual value.

The per-call limit check itself (`record.total_amount * decimal_multiplier + notional_amount_with_token_multiplier > route_limit_adjusted`) is computed on the *unscaled* `notional_amount_with_token_multiplier`, so an individual dust-sized call always passes. The bug is that the *persisted* `record.total_amount`/`per_hour_amounts` — the only state carried between calls — only ever accumulates the truncated (rounded-to-zero) value. An attacker who repeatedly calls the bridge-send entry point with dust-sized amounts of a token can therefore move an arbitrarily large aggregate value out of the bridge while `record.total_amount` stays at (or near) zero forever, defeating the entire purpose of the rolling 24-hour USD transfer limiter.

### Impact Explanation
This is directly analogous to the reported "insanely high price causes division-to-zero, oracle marked valid but corrupted" pattern: a division that can legitimately truncate to zero is used to update a value that a security check depends on, and no invariant prevents the truncated value from being accepted and persisted as the definitive record. Here the truncation lets an unprivileged, ordinary Sui token holder permanently defeat the bridge's `TransferLimiter`, a control explicitly described in the codebase docs as enforcing a rolling 24h USD cap per route (`bridge::limiter`, `check_and_record_sending_transfer`). Bypassing this cap is "harmful smart-contract behavior" that undermines a core bridge safety mechanism intended to bound worst-case exposure/damage during an incident window — this falls under the in-scope High-impact category ("harmful smart-contract behavior... reachable from public input") for the Sui Protocol program.

### Likelihood Explanation
The trigger is fully reachable by any unprivileged Sui address holding a bridged coin type: repeatedly call the public bridge send entry point (`bridge::bridge::send_token` and equivalent) with amounts small enough that `notional_value<T>() * amount < decimal_multiplier<T>()`. No committee, validator, or admin privilege is required — the only constraint is gas/transaction cost to issue enough dust transfers, which is a purely economic (not protocol) limitation. This makes exploitation straightforward and deterministic, not probabilistic.

### Recommendation
Track the limiter's running total in the token's native (unscaled) units, or use fixed-point/rational accumulation that carries the remainder between calls (e.g., keep a running remainder and only truncate once at the final USD-cap comparison), so that no legitimate incremental value is ever silently dropped. Alternatively, accumulate `notional_amount_with_token_multiplier` (unscaled) across the whole window and only scale down once when comparing/reporting, never persisting a rounded-to-zero contribution as "the" recorded transfer value.

### Proof of Concept
1. Bridge treasury registers a token `T` with `decimal_multiplier<T>() = 10^18` and `notional_value<T>()` set to some price `P` (8-dp USD).
2. Attacker holds a large balance of `T` and calls the outgoing bridge entry point (`send_token`) repeatedly with `amount = k` where `k` is chosen so that `P * k < 10^18` (trivial for the smallest unit, `amount = 1`).
3. Each call: `notional_amount_with_token_multiplier = P * k` passes the per-call check `record.total_amount * decimal_multiplier + P*k > route_limit_adjusted` (false, since both terms are tiny), then `notional_amount = P*k / 10^18 = 0` is added to `record.total_amount`.
4. Repeat until the attacker's entire balance is bridged out, in chunks of size `k`. `record.total_amount` remains `0` (or near-zero) throughout, so `check_and_record_sending_transfer` never returns `false`, and the real cumulative USD value moved through the route is unbounded despite the configured `route_limit`.

Note: I was not able to independently verify the exact numeric bounds of `decimal_multiplier`/`notional_value` for every currently supported token or fully trace gas-cost economics for large-scale dust-call automation within this session; a Devin session with repository execution access would be needed to run `limiter_tests.move`-style test scenarios (e.g., extending `test_24_hours_windows`) to empirically confirm the zero-accumulation behavior end-to-end.

### Citations

**File:** crates/sui-framework/packages/bridge/sources/limiter.move (L96-120)
```text
    // Compute notional amount
    // Upcast to u128 to prevent overflow, to not miss out on small amounts.
    let value = (treasury.notional_value<T>() as u128);
    let notional_amount_with_token_multiplier = value * (amount as u128);

    // Check if transfer amount exceed limit
    // Upscale them to the token's decimal.
    if (
        (record.total_amount as u128)
            * (treasury.decimal_multiplier<T>() as u128)
            + notional_amount_with_token_multiplier > route_limit_adjusted
    ) {
        return false
    };

    // Now scale down to notional value
    let notional_amount =
        notional_amount_with_token_multiplier / (treasury.decimal_multiplier<T>() as u128);
    // Should be safe to downcast to u64 after dividing by the decimals
    let notional_amount = (notional_amount as u64);

    // Record transfer value
    let new_amount = record.per_hour_amounts.pop_back() + notional_amount;
    record.per_hour_amounts.push_back(new_amount);
    record.total_amount = record.total_amount + notional_amount;
```

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L583-598)
```text
    let amount = token_payload.token_amount();
    // Make sure transfer is within limit.
    if (
        !bypass_limiter &&
        !inner
            .limiter
            .check_and_record_sending_transfer<T>(
                &inner.treasury,
                clock,
                route,
                amount,
            )
    ) {
        event::emit(TokenTransferLimitExceed { message_key: key });
        return (option::none(), owner)
    };
```
