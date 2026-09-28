### Title
Pool `repay` refunds declared-but-never-transferred "overpayment" out of real custody, draining reserves while the cash book still claims solvency - (File: contracts/pool/src/ops/repay.rs)

### Summary
The MSG_PEEK bug class is a "read" that silently takes ownership of a resource the caller never releases — a leak between what was *referenced* and what was *received*. The XOXNO Lending analog sits in the pool's repay leg: `ops::repay::accounting` resolves an `overpayment` purely from the *declared* `action.amount` versus the outstanding debt, and `ops::repay::apply` pays that overpayment out of the pool's real token custody via `cache.transfer_out(payer, overpayment)` without ever measuring what actually arrived. The refund does not debit `cash` and does not pass `require_reserves`. A repay whose declared amount was never transferred in drains live custody while the accounting book is untouched — a custody/book leak directly analogous to the orphaned skb.

### Finding Description
In `contracts/pool/src/ops/repay.rs`, `accounting` computes `(burned, overpayment) = cache.resolve_repay(amount, position)` from the declared `action.amount` [1](#0-0) . `apply` then refunds `overpayment` to `payer` from custody [2](#0-1) . Only `net_repay` is credited to `cash` via `cache.credit_cash(net_repay)`; the refund path performs no balance measurement of the inbound transfer and no cash debit.

When a position has no outstanding debt, `current_debt_ceil` is zero, the full-close branch makes `net_repay == 0`, and the *entire* declared amount becomes overpayment — refunded out of custody with nothing ever transferred in. The in-repo test `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` pins exactly this: `repay(&payer, &t.ract(0, custody_before))` credits `actual_amount == 0`, leaves `payer` holding the full declared amount, leaves pool custody at 0, and leaves `cash` unchanged [3](#0-2) . The same gap exists in `ops::recapitalize::apply` (excess over the shortfall refunded from custody), per the test's own comment [4](#0-3) .

This is the protocol-side twin of MSG_PEEK: the refund path "peeks" at a declared amount, treats it as a received balance (takes a reference), and never verifies the increment actually happened (never releases/reconciles the reference).

### Impact Explanation
An attacker repays a zero-debt (or dust-debt) position with a declared `amount` equal to the pool's token balance and receives the full custody as "overpayment refund" — direct theft of supplier funds. Because `cash` is never debited, the book keeps reporting the drained funds as present; `Cache::require_reserves` reads the book, so the market continues to admit borrows/withdraws that then fail inside the SAC transfer — a secondary freeze of all remaining user funds and false solvency reporting. Both theft of user funds and protocol insolvency criteria are met.

### Likelihood Explanation
The repay leg is reachable through the unprivileged `repay` entrypoint (and the same shape exists in `recapitalize`). No privileges, timing, or oracle manipulation are required — only a declared amount larger than the real debt, with the inbound leg absent or minimal. Note on scope caveat: whether the pool's `repay` can be invoked directly by a non-controller caller (versus only via controller, which pre-funds the transfer) could not be fully verified within the index; the unit test invokes the pool client's `repay` directly with an arbitrary `payer`, which suggests no caller allowlist, but if production restricts pool entrypoints to the controller, reachability narrows to paths where declared vs. transferred amounts can diverge (e.g., fee-on-transfer or weird tokens), weakening but not eliminating the finding.

### Recommendation
Measure the inbound transfer (balance-delta of the pool before/after the funding transfer) and cap `overpayment` at `received - net_repay` rather than `declared - debt`, or require `transfer_amount_measured`-style receipt verification before any refund. Debit the refund against `cash`/route it through `require_reserves`, and apply the same fix to `ops::recapitalize::apply`.

### Proof of Concept
1. Market exists with `borrowed == 0` and pool token custody `C > 0` (suppliers funded it).
2. Attacker calls pool `repay` with `PoolAction { position: empty/zero-scaled, amount: C }` and performs no inbound transfer (or a dust transfer on a manipulated path).
3. `resolve_repay` sees zero debt → `overpayment = C`, `net_repay = 0`; `RepayRoundsToZeroShares` passes on its `net_repay == 0` disjunct.
4. `cache.transfer_out(payer, C)` sends the entire custody to the attacker; `cash` remains unchanged.
5. Suppliers' subsequent `withdraw` passes `require_reserves` (book still shows `C`) and then reverts in the token transfer — funds permanently frozen/stolen. This is demonstrated by `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` in `contracts/pool/tests/flows.rs:3590`.

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

**File:** contracts/pool/src/ops/repay.rs (L40-47)
```rust
pub(crate) fn accounting(env: &Env, action: &PoolAction) -> RepayOutcome {
    let (mut cache, position) = ops::load_leg(env, action);
    let amount = action.amount;

    let (burned, overpayment) = cache.resolve_repay(amount, position);
    let net_repay = amount
        .checked_sub(overpayment)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));
```

**File:** contracts/pool/tests/flows.rs (L3376-3402)
```rust
/// Shared tail of the unfunded-refund tests: the declared amount came back to
/// the payer, custody is gone, and the cash book did not move.
fn assert_unfunded_refund_drained_custody(
    t: &TestSetup,
    payer: &Address,
    declared: i128,
    before: &PoolStateRaw,
) {
    let token = token::Client::new(&t.env, &t.asset);
    let after = t.state_snapshot();
    assert_eq!(
        token.balance(payer),
        declared,
        "the payer is refunded in full for a payment that never happened"
    );
    assert_eq!(
        token.balance(&t.pool),
        0,
        "the pool's entire custody has left the contract"
    );
    assert_eq!(
        after.cash, before.cash,
        "the cash book is untouched, so the pool still reports the paid-out \
         funds as present"
    );
    assert_pool_state_eq(&after, before);
}
```

**File:** contracts/pool/tests/flows.rs (L3589-3611)
```rust
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
}
```
