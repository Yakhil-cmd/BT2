### Title
`Pool::recapitalize` refunds an unfunded injection out of supplier custody, draining the pool while the cash book stays untouched - (File: contracts/pool/src/ops/recapitalize.rs)

### Summary
The kernel bug (CVE-2021-47416) is a state-machine error: `mdiobus_free` picked the `MDIOBUS_ALLOCATED` cleanup branch (`kfree`) even though `device_register()` had already run, so the `put_device()` cleanup needed by the real state was skipped. The analog in XOXNO Lending is `recapitalize`: the pool trusts the declared `amount` as if the funding leg already happened, books `applied = min(amount, backing_shortfall)` into cash, and pays `refund = amount - applied` back to `payer` out of pool custody — without ever measuring that `amount` was actually transferred in. The "cleanup" (refund) runs against a state that was never established, so custody leaves the contract while the books are unchanged.

### Finding Description
`recapitalize::accounting` computes the refund purely from the caller-supplied `amount` argument, not from a balance delta: `applied = amount.min(backing_shortfall(&cache))` and `refund = amount - applied`, crediting only `applied` to `cash` [1](#0-0) . `apply` then unconditionally executes `outcome.cache.transfer_out(&payer, outcome.refund)` [2](#0-1) . The doc comment states the invariant — "The controller transfers `amount` into the pool before this call" [3](#0-2)  — but nothing in the pool enforces it; there is no measured-receipt check (no pre/post `token.balance` comparison). When the market has no backing shortfall, `applied = 0` and the entire `amount` becomes the refund.

The repo's own regression test demonstrates this: calling `recapitalize(&hub_asset, &payer, &custody)` with no token transfer leaves `token.balance(&pool) == 0` while `cash` still reports the funds present, and a later withdraw passes `require_reserves` only to fail inside the SAC transfer [4](#0-3) .

### Impact Explanation
An unprivileged attacker calls `recapitalize` directly on the pool (it is a public entrypoint, `contracts/pool/src/lib.rs`) with `payer` set to an address they control, `hub_asset` pointing at a healthy market (zero backing shortfall), and `amount` equal to the market's full token custody. They authorize the call as `payer` but transfer nothing in. `transfer_out` sends `refund = amount` of the pool's SAC tokens to the attacker — direct theft of supplier funds. In the best case for the attacker this drains the market; in the worst case (partial shortfall) they still capture `amount - applied`. Any surviving suppliers are left with a `cash` book that overstates custody, so their withdrawals fail inside the token transfer — permanent freezing/insolvency for the remainder. Both accepted impact classes (theft of user funds, contract unable to operate from lack of token funds) are hit.

### Likelihood Explanation
A single unprivileged transaction is sufficient: no governance, no oracle manipulation, no timing dependency. The only prerequisites are a listed `hub_asset` whose pool holds tokens and that the `recapitalize` entrypoint requires at most `payer.require_auth()` — which the attacker self-satisfies. The existing test proves the unfunded path executes end-to-end [5](#0-4) .

### Recommendation
Measure the receipt instead of trusting `amount`: record `token.balance(pool)` before, require the caller (or controller) to push funds, and derive `applied`/`refund` from the measured delta — matching the pattern used elsewhere for exact-balance settlement. Alternatively, restrict `recapitalize` to the controller contract (auth check against a stored controller address) and have the controller perform the transfer and the pool call atomically within one invocation, so the unfunded state is unreachable.

### Proof of Concept
```rust
// Attacker-controlled payer; no tokens are moved into the pool.
let custody = token.balance(&pool);           // e.g. all supplier deposits
// Market is healthy => backing_shortfall == 0 => applied == 0, refund == amount.
pool_client.recapitalize(&hub_asset_key, &attacker, &custody);
// Result: attacker receives `custody` tokens; pool balance == 0;
// pool cash book unchanged; subsequent withdraw() fails in the SAC transfer.
```
This mirrors `test_unfunded_recapitalize_leaves_the_cash_book_overstating_custody` in `contracts/pool/tests/flows.rs`, which already exercises the unfunded-refund drain against the real contract client.

### Citations

**File:** contracts/pool/src/ops/recapitalize.rs (L3-4)
```rust
//! Only the shortfall amount is applied; any excess is refunded to the payer.
//! The controller transfers `amount` into the pool before this call.
```

**File:** contracts/pool/src/ops/recapitalize.rs (L32-37)
```rust
    let outcome = accounting(env, hub_asset, amount);

    outcome.cache.transfer_out(&payer, outcome.refund);

    events::emit_market_state(env, outcome.cache.snapshot());
    outcome.mutation
```

**File:** contracts/pool/src/ops/recapitalize.rs (L52-57)
```rust
    let applied = amount.min(guards::backing_shortfall(&cache));
    let refund = amount
        .checked_sub(applied)
        .unwrap_or_else(|| panic_with_error!(env, GenericError::MathOverflow));

    cache.credit_cash(applied);
```

**File:** contracts/pool/tests/flows.rs (L3407-3443)
```rust
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
```
