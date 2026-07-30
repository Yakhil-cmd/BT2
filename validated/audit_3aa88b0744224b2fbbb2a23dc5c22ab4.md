### Title
Cancel-order path in DeepBook v1 (`clob.move`) can permanently lock a maker's quote balance via arithmetic-abort-on-zero, mirroring the Velocimeter fee-rounds-to-zero revert - ([File: crates/sui-framework/packages/deepbook/sources/clob.move])

### Summary
`deepbook::clob` (DeepBook v1) computes the quote-asset amount to unlock for a cancelled bid order with `clob_math::mul(order.quantity, order.price)`. Unlike DeepBook v2 (`clob_v2.move`), which was hardened to use `clob_math::unsafe_mul_round` (never aborts, just returns the rounded value), v1 still calls `math::mul`, which explicitly asserts the multiplication result is non-zero and aborts with `EUnderflow` otherwise. This is the exact same root cause as the Velocimeter M-2 report: a value that is mathematically valid (quantity > 0, price > 0) can round down to zero under the fixed-point scaling, and a downstream function that requires a non-zero result then unconditionally reverts.

### Finding Description
`deepbook::math::mul` / `mul_round` are defined to reject a rounded-to-zero result: [1](#0-0) 

`deepbook::clob` (v1) uses this unsafe variant when unlocking a bid's locked quote balance during cancellation, batch cancellation, and expired-order cleanup: [2](#0-1) [3](#0-2) 

Compare this to `deepbook::clob_v2`, which was fixed to use `unsafe_mul_round` (no assertion, silently accepts a zero/rounded value) for the identical computation: [4](#0-3) 

If `order.quantity * order.price / FLOAT_SCALING_U128` rounds down to exactly `0` (achievable with small quantities and/or prices, or low-decimal base/quote assets scaled into the 10^9 fixed-point representation used by DeepBook), `clob_math::mul` aborts with `EUnderflow` inside `cancel_order`, `batch_cancel_order`, and `clean_up_expired_orders` in the v1 module. Because the computation is a pure deterministic function of the order's immutable `quantity`/`price` fields, every retry of cancellation for that exact order reproduces the identical abort — the transaction can never succeed through this code path, and the user's locked quote balance in `pool.quote_custodian` is never released via `custodian::unlock_balance`.

### Impact Explanation
This maps to the "permanent fund lock" High-impact class: a maker's locked quote-asset balance backing a small/low-priced bid order becomes permanently unreachable through the only order-cancellation code path in this module, because the unlock computation deterministically aborts every time it is invoked for that order. Unlike the swap-fee case in the original report (where the fix is simply "skip sending a zero fee"), here the aborting function's return value (`balance_locked`) is actually needed to perform the unlock — it cannot simply be skipped, so there is no user-triggerable workaround.

### Likelihood Explanation
Likelihood depends on two unverified conditions I could not fully confirm within the available search budget:
1. Whether `deepbook::clob` v1 pools/orders are still creatable or only pre-existing (I confirmed `create_pool`, `deposit_base/quote`, `swap_exact_*`, and `place_market_order` in v1 are explicitly `#[deprecated]` and `abort`, but I was unable to fully verify the deprecation status of `place_limit_order`/`match_*` and thus whether new bid orders reaching a zero-rounding quantity/price combination can still be placed in v1 pools today).
2. Whether an alternate release path (e.g., order matching/fill) also passes through `clob_math::mul` and would likewise abort, versus release still being reachable via a different, unaffected function.

Because DeepBook v1 is a legacy, largely deprecated module and v2 already replaced the vulnerable call with the safe rounding variant, the practical reachability on live, current-value pools is uncertain and may be low. I am flagging this explicitly rather than asserting exploitability with confidence.

### Recommendation
For any still-reachable code in `deepbook::clob` (v1) that computes locked/unlocked balances from `quantity * price`, replace `clob_math::mul` with `clob_math::unsafe_mul_round` (as already done in `clob_v2.move`), so a rounded-to-zero balance is unlocked as zero rather than aborting the entire cancellation transaction. If v1 order placement is fully deprecated and no new orders using this path can be created, this finding is moot for new activity but could still strand any legacy resting orders that satisfy the zero-rounding condition.

### Proof of Concept
Conceptual PoC (mirrors the report's PoC structure), pending confirmation that v1 order placement is still reachable:
1. Place a bid limit order on a `deepbook::clob::Pool` with `quantity` and `price` chosen such that `quantity * price / FLOAT_SCALING_U128 == 0` (e.g., very small quantity and/or price near the pool's tick/lot minimums, or a low-decimal quote asset scaled such that the 10^9 fixed-point product underflows to zero).
2. Call `cancel_order` (or `batch_cancel_order` / `clean_up_expired_orders`) for that order.
3. Observe the transaction abort with `EUnderflow` from `deepbook::math::mul`, called via `clob_math::mul(order.quantity, order.price)` inside `remove_order`'s caller.
4. Repeat cancellation — the abort recurs deterministically since `order.quantity`/`order.price` are fixed, leaving the locked quote balance stuck in `pool.quote_custodian` indefinitely through this path. [1](#0-0) [4](#0-3)

### Citations

**File:** crates/sui-framework/packages/deepbook/sources/math.move (L29-35)
```text
    // multiply two floating numbers and assert the result is non zero
    // Note that this function will still round down
    public fun mul(x: u64, y: u64): u64 {
        let (_, result) = unsafe_mul_round(x, y);
        assert!(result > 0, EUnderflow);
        result
    }
```

**File:** crates/sui-framework/docs/deepbook/clob.md (L1132-1137)
```markdown
    <b>if</b> (is_bid) {
        <b>let</b> balance_locked = clob_math::mul(order.quantity, order.price);
        <a href="../deepbook/custodian.md#deepbook_custodian_unlock_balance">custodian::unlock_balance</a>(&<b>mut</b> pool.quote_custodian, user, balance_locked);
    } <b>else</b> {
        <a href="../deepbook/custodian.md#deepbook_custodian_unlock_balance">custodian::unlock_balance</a>(&<b>mut</b> pool.base_custodian, user, order.quantity);
    };
```

**File:** crates/sui-framework/docs/deepbook/clob.md (L1299-1304)
```markdown
        <b>if</b> (is_bid) {
            <b>let</b> balance_locked = clob_math::mul(order.quantity, order.price);
            <a href="../deepbook/custodian.md#deepbook_custodian_unlock_balance">custodian::unlock_balance</a>(&<b>mut</b> pool.quote_custodian, user, balance_locked);
        } <b>else</b> {
            <a href="../deepbook/custodian.md#deepbook_custodian_unlock_balance">custodian::unlock_balance</a>(&<b>mut</b> pool.base_custodian, user, order.quantity);
        };
```

**File:** crates/sui-framework/packages/deepbook/sources/clob_v2.move (L751-752)
```text
                let (_is_round_down, balance_locked) = clob_math::unsafe_mul_round(order.quantity, order.price);
                custodian::unlock_balance(&mut pool.quote_custodian, owner, balance_locked);
```
