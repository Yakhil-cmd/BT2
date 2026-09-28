### Title
Pool `repay`/`recapitalize` refund a caller-declared amount out of real token custody without verifying any inbound payment - (File: contracts/pool/src/ops/repay.rs)

### Summary
The SQL-injection bug class — a caller-supplied parameter trusted to identify/size a record without validation — maps onto the pool's repay and recapitalize legs: both compute a refund purely from the *declared* `action.amount`/`amount` argument, not from a measured inbound token receipt, and pay that refund out of the pool's real token custody. The code comment states the assumption ("The controller transfers the repay amount into the pool before this call"), but nothing in `ops::repay::apply` or `ops::recapitalize::apply` measures the pool's balance delta or enforces that the transfer happened.

### Finding Description
`ops::repay::apply` calls `accounting`, which resolves `overpayment = amount - debt_retired` and then `cache.transfer_out(payer, outcome.overpayment)` moves real tokens from pool custody to `payer` [1](#0-0) . When the action targets a position with no debt, `resolve_repay` takes the full-close branch with `net_repay = 0`, so the entire declared amount becomes "overpayment" [2](#0-1) . The `RepayRoundsToZeroShares` assert explicitly passes on its `net_repay == 0` disjunct, so a purely fabricated repayment succeeds [3](#0-2) . The refund leg never debits `cash` and never passes `require_reserves`; it transfers directly out of custody.

`ops::recapitalize::apply` has the identical shape: `applied = min(amount, backing_shortfall)`, `refund = amount - applied`, then `transfer_out(&payer, refund)` — again derived from the declared `amount`, not from a measured receipt [4](#0-3) . On a healthy market `backing_shortfall` is zero, so the entire declared `amount` is refunded out of custody while `cash` is credited with zero.

The codebase's own test suite pins both drains: `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` calls `pool.repay` with nothing transferred in and no debt, and asserts the pool's real custody is paid out to the payer [5](#0-4) , and `test_unfunded_recapitalize_is_bounded_by_custody_not_by_the_declared_amount` shows the only bound on the payout is live token custody, reverting only when `amount` exceeds what the pool holds [6](#0-5) .

### Impact Explanation
If `pool::repay` or `pool::recapitalize` is reachable by an arbitrary address (the test harness invokes `t.client().repay(&payer, ...)` directly with a generated payer, implying no controller-only gate on the pool client path), an attacker declares `amount` equal to the pool's token balance on a market/position with zero debt, receives the full custody as a "refund", and repeats per (hub, token) book sharing the physical balance — direct theft of all user-supplied funds. Even if the pool is controller-gated, the refund primitive is still unfunded whenever a controller path credits a declared rather than measured inbound amount, so the same gap is one accounting bug away from draining reserves. I could not fully verify the authorization guard on `pool::repay`/`pool::recapitalize` within the available iterations; the tests demonstrate the drain executes when called directly.

### Likelihood Explanation
A single unprivileged transaction: call `repay` (or `recapitalize` on a market with no shortfall) with `payer = attacker` and `amount = pool token balance`. No debt, no collateral, no price manipulation, and no prior funding is required — the "payment" is purely declarative, exactly like the injected `table` parameter in CVE-2019-16692 being trusted without validation. Likelihood is high conditional on direct reachability of the pool entrypoint; through the controller the controller's own transfer-in normally funds the declared amount, which is the only reason the assumption in the doc comment holds.

### Recommendation
Measure the receipt instead of trusting the argument: snapshot the pool's token balance before the leg and cap `overpayment`/`refund` at `min(declared_excess, measured_balance_delta)`, or restrict `repay`/`recapitalize` to the controller and have the controller pass the measured transferred amount rather than the user-declared one. Alternatively, debit `cash` for the refund and run `require_reserves`, so an unfunded refund cannot exceed the book.

### Proof of Concept
1. Identify a live market `(hub_id, asset)` whose pool holds `C` tokens of `asset` and where the attacker has no debt position (use `position_id`/book with zero `scaled_debt`).
2. Call `pool.repay(attacker, [(HubAssetKey{hub_id, asset}, PoolAction{amount: C})])` — no token transfer is made.
3. `resolve_repay` sees `current_debt_ceil == 0`, sets `overpayment = C`, `net_repay = 0`; the `net_repay == 0` disjunct passes the assert.
4. `cache.transfer_out(attacker, C)` transfers the pool's entire real custody of `asset` to the attacker; books are untouched.
5. Equivalently, `pool.recapitalize(HubAssetKey{hub_id, asset}, attacker, C)` on a market with `backing_shortfall == 0` refunds `C` out of custody. The bundled tests `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` and `test_unfunded_recapitalize_is_bounded_by_custody_not_by_the_declared_amount` already execute both paths and show the payout is bounded only by live custody.

### Citations

**File:** contracts/pool/src/ops/repay.rs (L25-34)
```rust
pub(crate) fn apply(
    env: &Env,
    payer: &Address,
    action: &PoolAction,
) -> (PoolPositionMutation, MarketStateSnapshot) {
    let outcome = accounting(env, action);

    outcome.cache.transfer_out(payer, outcome.overpayment);
    (outcome.mutation, outcome.snapshot)
}
```

**File:** contracts/pool/src/ops/repay.rs (L44-57)
```rust
    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
        .checked_sub(overpayment)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));
    assert_with_error!(
        env,
        net_repay == 0 || burned.raw() > 0,
        GenericError::RepayRoundsToZeroShares
    );

    let position = position.checked_sub(env, burned);
    cache.burn_debt(burned);

    cache.credit_cash(net_repay);
```

**File:** contracts/pool/src/ops/recapitalize.rs (L44-67)
```rust
pub(crate) fn accounting(
    env: &Env,
    hub_asset: HubAssetKey,
    amount: i128,
) -> RecapitalizationOutcome {
    require_nonneg_amount(env, amount);
    let mut cache = ops::renewed_market(env, &hub_asset);

    let applied = amount.min(guards::backing_shortfall(&cache));
    let refund = amount
        .checked_sub(applied)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));

    cache.credit_cash(applied);
    cache.commit();

    RecapitalizationOutcome {
        cache,
        mutation: PoolAmountMutation {
            actual_amount: applied,
        },
        refund,
    }
}
```

**File:** contracts/pool/tests/flows.rs (L3497-3512)
```rust
    let outcome = t
        .client()
        .try_recapitalize(&hub(&t.asset), &payer, &(custody + 1));

    assert!(
        outcome.is_err(),
        "over-claiming past custody must not succeed"
    );
    assert_eq!(
        token.balance(&t.pool),
        custody,
        "a reverted over-claim leaves custody intact"
    );
    assert_eq!(token.balance(&payer), 0);
    assert_eq!(t.state_snapshot().cash, before.cash);
}
```

**File:** contracts/pool/tests/flows.rs (L3590-3611)
```rust
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
}
```
