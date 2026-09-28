### Title
Unfunded overpayment refunds drain pool custody via declared-amount `repay` / `recapitalize` - (File: contracts/pool/src/ops/repay.rs)

### Summary
The pool computes overpayment refunds from the *declared* `action.amount`, not from measured inbound receipts. `ops::repay::apply` transfers the full excess back to `payer` via `cache.transfer_out` without debiting `cash` or requiring that the declared amount was ever transferred in. When the market has no outstanding debt, `resolve_repay` takes the full-close branch, `net_repay` is zero, and the entire declared amount is refunded out of real token custody. The same gap exists in `ops::recapitalize::apply`, where `refund = amount - applied` is paid out against a `backing_shortfall` of zero. This mirrors the double-free bug class: the same pool balance is "released" twice — once as legitimate supplier backing and again as an unearned refund — because the release is keyed to an unverified declaration rather than a one-time resource.

### Finding Description
In `contracts/pool/src/ops/repay.rs`, `accounting` resolves `(burned, overpayment)` from `action.amount` and the position's debt, credits only `net_repay = amount - overpayment` to cash, and `apply` then calls `outcome.cache.transfer_out(payer, outcome.overpayment)` [1](#0-0) . The refund path never checks that `amount` tokens actually arrived; the comment "The controller transfers the repay amount into the pool before this call" is a trust assumption, not an enforcement [2](#0-1) . The `RepayRoundsToZeroShares` assert explicitly permits the `net_repay == 0` case [3](#0-2) .

`ops::recapitalize::accounting` has the identical shape: `applied = amount.min(backing_shortfall)` and `refund = amount - applied`, then `transfer_out(&payer, refund)` [4](#0-3) [5](#0-4) .

The codebase's own regression test proves the drain: `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` calls `repay` with no inbound transfer and asserts the entire declared amount (equal to pool custody) is paid out of real custody with the book untouched [6](#0-5) .

### Impact Explanation
An unprivileged caller can extract the full token balance of any debt-free pool market by declaring `amount = pool_balance` on a repay leg. Suppliers' deposited cash is paid to the attacker while `cash`, `supplied`, and share accounting remain unchanged — the book still shows full backing that no longer exists, so this is both theft of user funds and protocol insolvency (later withdraws revert on missing custody). Repeating across markets drains the pool entirely.

### Likelihood Explanation
The only mitigating factor is whether the pool's `repay`/`recapitalize` entrypoints enforce controller auth. I could not fully confirm the auth check on the pool contract's public functions within the available iterations — `lib.rs` grep matched on controller-related tokens but the exact gate is unverified. If the pool trusts its caller (as the doc comments imply, with custody enforcement delegated to the controller), the attack is a single permissionless call per market and requires no capital. If the pool hard-requires the controller address, the controller does transfer funds in before the call, which would neutralize this path — that check is the crux and should be verified first.

### Recommendation
Measure inbound receipts instead of trusting `action.amount`: snapshot the pool's token balance before/after, or require the controller to report a measured receipt, and compute `overpayment` as `min(declared_excess, measured_inbound)`. Alternatively, gate `repay` and `recapitalize` on `require_auth` of the configured controller address. Add a `require_reserves`/`cash` debit check on every `transfer_out` refund.

### Proof of Concept
See `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` in `contracts/pool/tests/flows.rs:3590-3611`: on a market with zero debt, call `repay(payer, PoolAction { amount = pool_balance, .. })` with no token transfer in; `resolve_repay` returns `overpayment = amount`, `net_repay = 0`, and `transfer_out` pays `pool_balance` to `payer`. The same sequence works on `recapitalize` when `backing_shortfall == 0` (`applied = 0`, `refund = amount`).

### Citations

**File:** contracts/pool/src/ops/repay.rs (L1-5)
```rust
//! Repay leg: burn debt shares, credit cash, refund overpayment to the payer.
//!
//! The controller transfers the repay amount into the pool before this call.

use common::errors::GenericError;
```

**File:** contracts/pool/src/ops/repay.rs (L30-34)
```rust
    let outcome = accounting(env, action);

    outcome.cache.transfer_out(payer, outcome.overpayment);
    (outcome.mutation, outcome.snapshot)
}
```

**File:** contracts/pool/src/ops/repay.rs (L48-52)
```rust
    assert_with_error!(
        env,
        net_repay == 0 || burned.raw() > 0,
        GenericError::RepayRoundsToZeroShares
    );
```

**File:** contracts/pool/src/ops/recapitalize.rs (L32-34)
```rust
    let outcome = accounting(env, hub_asset, amount);

    outcome.cache.transfer_out(&payer, outcome.refund);
```

**File:** contracts/pool/src/ops/recapitalize.rs (L52-56)
```rust
    let applied = amount.min(guards::backing_shortfall(&cache));
    let refund = amount
        .checked_sub(applied)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));

```

**File:** contracts/pool/tests/flows.rs (L3583-3610)
```rust
///
/// A repay against a market with no debt makes the entire declared amount an
/// overpayment: `current_debt_ceil` is zero, so `resolve_repay` takes the
/// full-close branch and `net_repay` is zero. The `RepayRoundsToZeroShares`
/// assert in `ops::repay::accounting` passes on its `net_repay == 0` disjunct,
/// and the whole amount is refunded out of real custody with the book untouched.
#[test]
fn test_unfunded_repay_overpayment_refund_also_pays_out_of_custody() {
    let t = TestSetup::new();
    let token = token::Client::new(&t.env, &t.asset);
    let payer = Address::generate(&t.env);

    let custody_before = token.balance(&t.pool);
    let before = t.state_snapshot();
    assert_eq!(
        before.cash, custody_before,
        "fixture guard: book and custody must start in sync"
    );
    assert_eq!(before.borrowed, 0, "fixture must carry no debt");

    // Nothing transferred in, no debt to retire: the whole amount is "excess".
    let credited = t
        .client()
        .repay(&payer, &t.ract(0, custody_before))
        .get_unchecked(0)
        .actual_amount;
    assert_eq!(credited, 0, "no debt was retired, so nothing is credited");
    assert_unfunded_refund_drained_custody(&t, &payer, custody_before, &before);
```
