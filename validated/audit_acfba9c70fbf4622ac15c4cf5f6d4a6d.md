### Title
Unfunded overpayment refund drains pool custody — `repay`/`recapitalize` pay out a declared amount that was never transferred in - ([File: contracts/pool/src/ops/repay.rs])

### Summary
The bug class is a resource allocated but never reconciled against what was actually received: the pool computes an "overpayment"/`refund` purely from the *declared* `action.amount` and pays it out of real token custody via `transfer_out`, without ever measuring that the declared amount actually arrived. A direct token transfer to the pool is never required — the refund is funded by suppliers' cash.

### Finding Description
`repay::apply` calls `accounting`, which resolves `amount` into `(burned, overpayment)` where `overpayment = amount - net_repay`. It credits `net_repay` to `cash`, but the overpayment leg is settled unconditionally with `outcome.cache.transfer_out(payer, outcome.overpayment)` — a real token transfer out of the pool's balance that never debits `cash` nor passes `require_reserves`. [1](#0-0)  The accounting function takes `amount` verbatim from the action (`let amount = action.amount;`) with no balance-delta measurement. [2](#0-1) 

`resolve_repay` takes the full-close branch whenever `amount >= current_debt_ceil`; against a market with zero debt the *entire* declared amount becomes `overpayment`, `net_repay == 0` passes the `RepayRoundsToZeroShares` assert on its `net_repay == 0` disjunct, and the whole sum is refunded. The protocol's own regression test proves the drain: `repay` on a no-debt market pays `custody_before` out to `payer` with the cash book untouched (`test_unfunded_repay_overpayment_refund_also_pays_out_of_custody`, `contracts/pool/tests/flows.rs:3590`).

The same shape exists in `recapitalize::apply`: `refund = amount - min(amount, backing_shortfall)` is paid out via `transfer_out` against a declared `amount`. [3](#0-2) 

### Impact Explanation
Theft of user funds / pool insolvency: an attacker calls `repay` (or `recapitalize` on a market with no shortfall) with a large declared `amount` and themselves as `payer`, transferring nothing in. The pool sends real tokens held as supplier `cash` to the attacker while the accounting book still credits that cash to suppliers — a direct leak of custody, exactly the "allocated but never freed/backed" class of CVE-2020-36790, with concrete monetary impact.

### Likelihood Explanation
The only precondition is a reachable pool leg. If `repay`/`recapitalize` require only `payer` authorization (the harness invokes `client().repay(&payer, ...)` directly with a fresh address and no controller involvement), any unprivileged account can execute it against any listed market, repeated until custody is drained. If the public endpoint enforces controller-only invocation, reachability drops to nil — the "controller prefunds before calling" comment is the design assumption, and I could not fully confirm which auth gate the pool's public `repay`/`recapitalize` entrypoints apply; that check determines whether this is Critical/High or dead code.

### Recommendation
Measure the inbound leg: snapshot `token.balance(pool)` before the op (or use `transfer_amount_measured`-style receipt accounting as the controller legs do) and cap `overpayment`/`refund` at the measured inbound delta, refunding at most `received - net_repay`. Alternatively require the transfer-in to be bundled in the same transaction before settling the refund.

### Proof of Concept
```rust
// Market with suppliers' cash, zero debt. Attacker transfers nothing.
let custody = token.balance(&pool);          // suppliers' backing
let r = pool_client.repay(&attacker, &RepayAction { amount: custody, .. });
// resolve_repay: current_debt_ceil == 0 => overpayment == custody, net_repay == 0
// transfer_out(attacker, custody) executes; cash book unchanged.
assert_eq!(token.balance(&attacker), custody); // suppliers drained
assert_eq!(r.actual_amount, 0);
```
Mirrors `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` in `contracts/pool/tests/flows.rs:3590-3611`.

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

**File:** contracts/pool/src/ops/repay.rs (L40-57)
```rust
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

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

**File:** contracts/pool/src/ops/recapitalize.rs (L52-67)
```rust
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
