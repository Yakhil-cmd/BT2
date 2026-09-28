### Title
Unfunded overpayment refund in pool repay/recapitalize drains real custody with the cash book untouched — (File: contracts/pool/src/ops/repay.rs)

### Summary
The Linux bug class is a resource acquired on the entry path (`of_parse_phandle` refcount) that is released on the success path but leaked on the error/early-exit path. The analog in XOXNO Lending is the pool's *overpayment* early-exit leg: `ops::repay::accounting` and `ops::recapitalize::accounting` size the refund from the **declared** `action.amount`/`amount` rather than from any measured inbound receipt, and `apply` then transfers that refund out of pool custody without debiting `cash` or passing `require_reserves`. When the inbound leg delivers less than declared — including zero — the "excess" is still paid out, so custody decreases while the book still reports the funds as present.

### Finding Description
`repay::accounting` computes `(burned, overpayment) = cache.resolve_repay(amount, position)` where `overpayment = amount - outstanding_debt`, credits only `net_repay` to cash, and commits [1](#0-0) . `apply` then unconditionally does `cache.transfer_out(payer, overpayment)` [2](#0-1) . On a market with zero debt, `resolve_repay` takes the full-close branch, `net_repay` is 0, the `RepayRoundsToZeroShares` assert passes via its `net_repay == 0` disjunct, and the **entire declared amount** is refunded from real token custody.

`recapitalize::accounting` has the identical shape: `applied = amount.min(backing_shortfall)`, `refund = amount - applied`, credit `applied`, then `transfer_out(payer, refund)` [3](#0-2) [4](#0-3) . When the shortfall is zero, `refund == amount`.

Neither refund path measures the actual balance delta into the pool — it trusts the declared amount, which is the leaked "refcount": acquired on paper, never verified, and released as real tokens.

### Impact Explanation
The repo's own tests demonstrate the impact: `assert_unfunded_refund_drained_custody` asserts the payer is refunded in full for a payment that never happened, the pool's entire custody leaves the contract, and `cash` is untouched [5](#0-4) . `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` calls `repay` with no inbound transfer and drains `custody_before` from the pool [6](#0-5) . If the pool repay/recapitalize legs are reachable without the controller having transferred in (direct call, or any controller path where the measured receipt is smaller than the declared amount), this is theft of user funds: an attacker drains real token balances equal to the pool's excess custody over the book. Even at worst, it permanently desyncs `cash` from custody — the market reports solvency and later withdrawals fail inside the SAC transfer [7](#0-6) .

Caveat I could not fully verify within the available context: whether `pool.repay`/`pool.recapitalize` enforce that they are invoked only by the controller. If they do, reachability depends on a controller flow that declares `amount` larger than the tokens actually moved in — the measured-receipt settlement pattern in `payments.rs` suggests the controller normally balances this, but the pool leg itself never validates it.

### Likelihood Explanation
Single unprivileged call: `pool.repay(payer, PoolAction{hub_asset, amount = pool_token_balance})` on any zero-debt market, or `pool.recapitalize(hub_asset, payer, amount)` when the backing shortfall is zero. No price moves, no position, no prior state needed — only real custody sitting in the pool above the accounted book. Medium at minimum given the book/custody desync is proven by the in-repo test; High if the direct-call path is unauthenticated.

### Recommendation
Measure the refund against the actual inbound balance delta (record `balance_before` before the inbound leg and compute `excess = received - applied`), or debit `cash`/call `require_reserves` for the refund, or reject when the declared amount exceeds what was received. At minimum, gate `repay`/`recapitalize` on controller invocation and have the controller pass the measured received amount rather than the declared one — mirroring the `balance_delta_since`/`refund_controller_balance_delta` pattern already used in `contracts/controller/src/payments.rs` [8](#0-7) .

### Proof of Concept
The existing test is the PoC: seed a pool holding `custody_before` tokens with zero debt, then `client().repay(&payer, &ract(0, custody_before))` with no token transfer in. Result: `credited == 0`, payer balance increases by `custody_before`, pool token balance goes to 0, `cash` unchanged [9](#0-8) . The same holds for `recapitalize` with `backing_shortfall == 0`: `applied = 0`, `refund = amount`, paid out of custody [3](#0-2) .

### Citations

**File:** contracts/pool/src/ops/repay.rs (L30-33)
```rust
    let outcome = accounting(env, action);

    outcome.cache.transfer_out(payer, outcome.overpayment);
    (outcome.mutation, outcome.snapshot)
```

**File:** contracts/pool/src/ops/repay.rs (L44-60)
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

    let snapshot = cache.commit();
    let mutation = cache.position_mutation(position, net_repay);
```

**File:** contracts/pool/src/ops/recapitalize.rs (L32-34)
```rust
    let outcome = accounting(env, hub_asset, amount);

    outcome.cache.transfer_out(&payer, outcome.refund);
```

**File:** contracts/pool/src/ops/recapitalize.rs (L52-58)
```rust
    let applied = amount.min(guards::backing_shortfall(&cache));
    let refund = amount
        .checked_sub(applied)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));

    cache.credit_cash(applied);
    cache.commit();
```

**File:** contracts/pool/tests/flows.rs (L3384-3401)
```rust
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
```

**File:** contracts/pool/tests/flows.rs (L3404-3406)
```rust
/// After an unfunded refund, `cash` overstates custody. `Cache::require_reserves`
/// reads the book, not the balance, so it admits exits that then fail inside
/// the SAC transfer. The market reports itself solvent and cannot pay.
```

**File:** contracts/pool/tests/flows.rs (L3590-3610)
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
```

**File:** contracts/controller/src/payments.rs (L41-51)
```rust
pub(crate) fn refund_controller_balance_delta(
    env: &Env,
    asset: &Address,
    balance_before: i128,
    refund_to: &Address,
) {
    let controller = env.current_contract_address();
    let excess = balance_delta_since(env, asset, &controller, balance_before);
    if excess > 0 {
        token::Client::new(env, asset).transfer(&controller, refund_to, &excess);
    }
```
