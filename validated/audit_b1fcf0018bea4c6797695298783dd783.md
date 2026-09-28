### Title
Pool `repay` refunds the declared overpayment out of real custody without measuring receipt or debiting `cash` — (File: contracts/pool/src/ops/repay.rs)

### Summary
The CVE-2022-49915 class is a leaked reference: a resource is acquired but its release bookkeeping is skipped, so the accounted state and the real backing permanently diverge. The pool's `ops::repay::apply` commits `credit_cash(net_repay)` for the debt-burning portion, then transfers `overpayment` back to the payer via `cache.transfer_out`. The refund is computed from the *declared* `action.amount`, not from any measured inbound balance, and it is paid out of the pool's real token custody without debiting `cash`. The cash book therefore still reports the refunded tokens as present — a "leaked" accounting balance that can never be released.

### Finding Description
`repay::accounting` calls `cache.resolve_repay(amount, position)`, which splits the declared `amount` into `burned`/`net_repay` and `overpayment` based solely on the position's outstanding debt. `repay::apply` then unconditionally transfers `overpayment` out to `payer`. Only `net_repay` is credited to `cash`; the refund is never subtracted because the book assumes the full declared amount arrived. As the repo's own test `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` proves, a repay against a market with no debt (`current_debt_ceil == 0`, so `resolve_repay` takes the full-close branch and `net_repay == 0`) refunds the entire declared amount from custody, leaving `cash` and the rest of the pool state untouched — `assert_unfunded_refund_drained_custody` shows custody goes to 0 while `cash` is unchanged. The same shape exists in `ops::recapitalize::apply` (`refund = amount - applied` paid from custody). There is no measured-receipt check (no `balance_delta_since`-style verification) and no `require_reserves` guard on the refund leg.

### Impact Explanation
An unprivileged address calls `repay` (or `recapitalize`) declaring `amount` equal to the pool's token balance with zero or minimal actual transfer-in — e.g., on a market where their position has no debt, so the whole amount is "excess." The pool transfers real custody tokens to the attacker while `cash` still counts them. This is direct theft of user funds plus a permanent book/custody divergence: `Cache::require_reserves` reads the inflated book and admits withdrawals/borrows that then fail inside the SAC transfer, i.e., the market reports itself solvent but cannot pay — protocol insolvency and permanent freezing of remaining suppliers' funds.

### Likelihood Explanation
The attack needs only one externally callable entrypoint (`pool.repay` / `controller.repay` path where the leg reaches `ops::repay::apply`) and a debt-free position, which any fresh account satisfies. No privileged role, no oracle manipulation, no reentrancy — just a declared amount larger than actual debt. Repeatable on every market until custody is drained.

### Recommendation
Settle the repay/recapitalize legs on measured receipt: snapshot the pool's token balance before the expected inbound transfer (or measure the delta, as `transfer_amount_measured`/`balance_delta_since` do in the controller), and cap `overpayment`/`refund` at `min(declared_excess, actual_excess_received)`. Alternatively debit `cash` (or gate the refund through `require_reserves`) so the book cannot release tokens it still counts as backing.

### Proof of Concept
Repository test demonstrating the exploit: `contracts/pool/tests/flows.rs` `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` — a payer calls `repay` with `amount` equal to full pool custody and no inbound transfer; `credited == 0`, the payer's balance increases by the full declared amount, pool custody drops to 0, and `cash`/`borrowed` state are unchanged, leaving the book permanently overstating reserves. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** contracts/pool/src/ops/recapitalize.rs (L26-38)
```rust
pub(crate) fn apply(
    env: &Env,
    hub_asset: HubAssetKey,
    payer: Address,
    amount: i128,
) -> PoolAmountMutation {
    let outcome = accounting(env, hub_asset, amount);

    outcome.cache.transfer_out(&payer, outcome.refund);

    events::emit_market_state(env, outcome.cache.snapshot());
    outcome.mutation
}
```

**File:** contracts/pool/tests/flows.rs (L3578-3611)
```rust
/// The refund gap is not specific to `recapitalize`. Two pool legs refund an
/// excess derived from a declared inbound amount, not from the cash book:
/// `ops::recapitalize::apply` (the excess over the shortfall) and
/// `ops::repay::apply` (the excess over the debt). Neither refund debits `cash`
/// or passes `require_reserves`.
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
}
```
