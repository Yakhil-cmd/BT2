### Title
Unmeasured recapitalize/repay refund leg pays real token custody out of the pool without verifying any inbound transfer - ([File: contracts/pool/src/ops/recapitalize.rs])

### Summary
The external report is directory traversal: a path is resolved relative to a declared input, letting a request escape the intended root and read files it should not. The structural analog in XOXNO Lending is the pool's refund legs in `recapitalize` and `repay`: they compute a "refund" purely from a caller-declared `amount` and transfer real token custody out of the pool, outside the intended accounting root (`cash` book / reserves guards). The refund assumes the controller already transferred `amount` tokens in, but nothing on the pool side measures the actual inbound balance, so a caller who never moved funds in can still walk the refund leg out of custody.

### Finding Description
`ops::recapitalize::accounting` computes `applied = amount.min(backing_shortfall)` and `refund = amount - applied`, then `apply` calls `cache.transfer_out(&payer, refund)` paying the declared excess straight out of the pool's SAC balance [1](#0-0) . No balance-delta check ties the refund to an actual inbound transfer — the doc comment admits "The controller transfers `amount` into the pool before this call" is an assumption [2](#0-1) .

The same shape exists in `ops::repay::apply`: `resolve_repay` produces `overpayment = amount - net_repay`, and `overpayment` is transferred out of custody without debiting `cash` or passing `require_reserves` [3](#0-2) . On a market with zero outstanding debt, `net_repay` is 0 and the entire declared `amount` becomes "overpayment," refunded out of real custody with the book untouched.

The existing test `test_unfunded_recapitalize_leaves_the_cash_book_overstating_custody` demonstrates the full drain: a direct `pool.recapitalize(hub, payer, custody)` call moves every token the pool holds to `payer`, leaving `cash >= deposit` while `token.balance(&pool) == 0`; a legitimate supplier's withdraw then fails inside the SAC transfer (error 10), not in any pool guard [4](#0-3) . `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` pins the equivalent `repay` path [5](#0-4) .

### Impact Explanation
Theft of user funds plus permanent freezing. An unprivileged address declares `amount = pool balance` on a market with no backing shortfall (recapitalize) or no debt (repay), receives the entire token balance as a "refund," and leaves the `cash` book claiming funds that no longer exist in custody. Suppliers' withdraws then revert inside the SAC transfer: the pool reports solvency on the book and cannot pay, permanently freezing remaining claims until governance intervenes.

### Likelihood Explanation
No privileged role, oracle manipulation, or multi-block setup is needed — a single call to `pool::recapitalize(hub_asset, payer, amount)` (or `repay` against a zero-debt position) with `payer` = attacker suffices, since the refund path performs no auth on the payer, no inbound-balance measurement, and no reserve guard. The tests demonstrate it deterministically on a vanilla market. Whether the deployed pool gates `recapitalize` to the controller only is not visible in the indexed code; the tests call it directly with no auth mocking shown, and the same refund logic is reachable via the controller's `recapitalize` and `repay` entrypoints listed as in-scope.

### Recommendation
Make both legs measured-receipt: snapshot `token.balance(pool)` before accounting and require the post-call custody to equal `before + net_repay/applied` (i.e., refund only what was actually received in excess). Alternatively, have the controller pass the actual transferred-in amount (balance delta) rather than the declared `amount`, or debit the refund against `cash` and run `require_reserves` so the book cannot diverge from custody.

### Proof of Concept
From `contracts/pool/tests/flows.rs`:
```rust
// Market has a supplier's deposit; custody == cash book.
let custody = token.balance(&t.pool);
// Attacker calls recapitalize declaring the full balance; no tokens sent in.
t.client().recapitalize(&hub(&t.asset), &payer, &custody);
assert_eq!(token.balance(&t.pool), 0);        // pool fully drained
assert!(t.state_snapshot().cash >= deposit);  // book still claims the funds
// Supplier withdraw reverts inside the SAC (error 10), not a pool guard.
assert!(t.client().try_withdraw(&receiver, &false, &wdr).is_err());
```
The `repay` variant: `pool.repay(payer, act(position_id, amount))` on a zero-debt market makes `overpayment == amount` and drains custody identically.

### Citations

**File:** contracts/pool/src/ops/recapitalize.rs (L1-4)
```rust
//! Recapitalization: injects cash to cover a market backing shortfall.
//!
//! Only the shortfall amount is applied; any excess is refunded to the payer.
//! The controller transfers `amount` into the pool before this call.
```

**File:** contracts/pool/src/ops/recapitalize.rs (L26-55)
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

/// Sizes and books the cash injection without transferring tokens.
///
/// Credits `min(amount, backing_shortfall)` to cash and commits. `refund` is
/// `amount - applied`.
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
```

**File:** contracts/pool/src/ops/repay.rs (L25-57)
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

/// Accrues interest, resolves the repay amount into burned debt shares and
/// overpayment, burns the shares, and credits the net repay to cash without
/// transferring the overpayment refund. Panics if a positive net repay would
/// burn zero scaled shares.
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

**File:** contracts/pool/tests/flows.rs (L3430-3482)
```rust
    // Drain every token via an unfunded refund.
    let custody = token.balance(&t.pool);
    t.client().recapitalize(&hub(&t.asset), &payer, &custody);
    assert_eq!(token.balance(&t.pool), 0, "custody is gone");

    let book = t.state_snapshot().cash;
    assert!(
        book >= deposit,
        "the book still claims more than the supplier's deposit: {book}"
    );

    // The supplier's exit clears the pool's own liquidity guard -- the book
    // says the cash is there -- and then fails in the token transfer.
    let outcome = t
        .client()
        .try_withdraw(&receiver, &false, &t.wdr(supplied, i128::MAX, 0));
    assert!(
        outcome.is_err(),
        "the withdraw cannot be paid, so it must fail"
    );
    // The failure must come from custody, not from a pool guard. The SAC
    // reports insufficient balance as its own contract error `BalanceError = 10`.
    // The asserts check that exact code and that neither pool liquidity guard
    // fired: `require_reserves` read the book and let the exit through.
    const SAC_BALANCE_ERROR: u32 = 10;
    match outcome {
        Err(Ok(err)) => {
            assert_ne!(
                err,
                Error::from_contract_error(CollateralError::InsufficientLiquidity as u32),
                "the pool's own liquidity guard must NOT be what stopped this -- \
                 it reads the cash book, which still shows the funds"
            );
            assert_ne!(
                err,
                Error::from_contract_error(CollateralError::PoolInsolvent as u32),
                "the pool's solvency guard must NOT be what stopped this either"
            );
            assert_eq!(
                err,
                Error::from_contract_error(SAC_BALANCE_ERROR),
                "the exit must fail inside the SAC transfer for want of custody"
            );
        }
        Err(Err(host_abort)) => panic!("expected a SAC contract error, got {host_abort:?}"),
        Ok(_) => unreachable!("asserted is_err above"),
    }
    assert_eq!(token.balance(&receiver), 0, "the supplier received nothing");
    assert_eq!(
        t.state_snapshot().cash,
        book,
        "the failed exit rolled back, so the book still overstates custody"
    );
```

**File:** contracts/pool/tests/flows.rs (L3578-3610)
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
```
