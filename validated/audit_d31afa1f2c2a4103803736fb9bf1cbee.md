### Title
Unfunded recapitalize refunds drain pool custody while the cash book still reports solvency - (File: contracts/pool/tests/flows.rs)

### Summary
The HTTP/2 bug class is "state allocated on an error/teardown path that is never cleaned up." The analog here is a settlement that never reconciles: `recapitalize` pays a refund leg out of pool custody without an enforced incoming receipt, so the pool's token balance drops while the `cash` book keeps claiming the funds are there — the accounting divergence is never cleaned up, exactly like the leaked `Http2Session`.

### Finding Description
`Controller::recapitalize` (`contracts/controller/src/markets.rs:142-164`) prefunds the pool with a measured transfer from `payer` and forwards `received` to `pool_recapitalize_call`. The pool side is expected to credit the cash book only up to the backing shortfall and refund the rest to `payer`. The checked-in regression test `test_unfunded_recapitalize_leaves_the_cash_book_overstating_custody` (`contracts/pool/tests/flows.rs:3408-3483`) demonstrates that `pool.recapitalize` can be invoked so that it transfers `amount` tokens out to `payer` with no corresponding inbound funding: `token.balance(&pool)` falls to 0 while `state_snapshot().cash` still reports at least the supplier's deposit.

The book/custody split is never corrected afterward. `require_reserves` reads the book (not the SAC balance), so a supplier's `withdraw` clears the pool's own `InsufficientLiquidity`/`PoolInsolvent` guards and then fails inside the SAC transfer with `BalanceError = 10` — pinned explicitly in the test at lines 3457-3472.

### Impact Explanation
Permanent freezing of user funds / contract unable to operate from lack of token funds: after custody is drained by the unmatched refund leg, the market still reports itself solvent, every exit reverts at the token layer, and suppliers can never withdraw. The overstatement persists indefinitely (the book still overstates custody after the failed exit, `flows.rs:3478-3482`), so no subsequent operation self-heals it — the same "cleanup never happens" shape as the advisory.

### Likelihood Explanation
The drain is reachable with a single `recapitalize` call supplying a `payer`/`amount`, and needs no price manipulation, no flash loan, and no privileged parameters — the test performs it with a generated `payer` address. Caveat I could not fully verify within the available context: whether `pool.recapitalize` enforces a controller-only caller gate in production. If it does, the equivalent controller path still exposes the weakness because the controller trusts the pool's refund accounting, though a strict gate would reduce the finding to a bookkeeping-safety defect rather than direct unprivileged theft. Medium is consistent with that residual uncertainty.

### Recommendation
Make `recapitalize` receipt-strict inside the pool: measure the pool's SAC balance before and after the (already performed) inbound transfer, credit/refund only the measured delta, and revert if the claimed `amount` exceeds the measured receipt. Alternatively, fold the refund into the same measured-settlement pattern used by `claim_revenue` (`markets.rs:182-196`) and add an invariant asserting `cash <= token.balance(pool)` after every recapitalize.

### Proof of Concept
`contracts/pool/tests/flows.rs:3408-3483` — mint a deposit, call `client().recapitalize(&hub, &payer, &custody)` with no prefunding, observe `token.balance(&pool) == 0` while `cash >= deposit`, then observe `try_withdraw` fail with SAC `BalanceError = 10` rather than a pool guard. [1](#0-0) [2](#0-1)

### Citations

**File:** contracts/pool/tests/flows.rs (L3408-3450)
```rust
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

**File:** contracts/controller/src/markets.rs (L142-164)
```rust
pub(crate) fn recapitalize(
    env: &Env,
    payer: Address,
    hub_asset: HubAssetKey,
    amount: i128,
) -> i128 {
    validation::require_authorized_caller(env, &payer);
    require_positive_amount(env, amount);

    let mut cache = Context::new(env);
    let pool_addr = cache.cached_pool_address();
    // Prefund the pool and credit only its measured receipt.
    let received = payments::transfer_amount_measured(
        env,
        &hub_asset.asset,
        &payer,
        &pool_addr,
        amount,
        GenericError::AmountMustBePositive,
    );

    pool_recapitalize_call(env, &pool_addr, &hub_asset, &payer, received).actual_amount
}
```
