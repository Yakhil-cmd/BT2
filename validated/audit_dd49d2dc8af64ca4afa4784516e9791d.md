### Title
Refund legs pay out of pool custody without debiting `cash`, letting any caller drain the pool and leaving the cash book overstating real balance - (File: contracts/pool/src/ops/recapitalize.rs)

### Summary
The analog of the QV `poolAmount` bug: XOXNO's pool keeps a cached balance book `cash`, and liquidity guards (`Cache::require_reserves`) and payout sizing read the book while `Cache::transfer_out` moves real tokens without touching it. Two pool legs - `recapitalize`'s excess refund and `repay`'s overpayment refund - transfer real custody back to the caller based on a *declared* inbound `amount`, not on tokens actually received, and never debit `cash`. An unprivileged caller can therefore name themselves `payer`, declare `amount` equal to the pool's full balance, and receive the entire custody as an "unfunded refund", while the book still reports the funds as present.

### Finding Description
In `contracts/pool/src/ops/recapitalize.rs:44-66`, `accounting` computes `applied = amount.min(backing_shortfall)` and `refund = amount - applied`; in a healthy market the shortfall is zero, so `applied == 0` and `refund == amount`. `apply` then calls `outcome.cache.transfer_out(&payer, outcome.refund)` (line 34). The same pattern exists in `contracts/pool/src/ops/repay.rs:44-47` and `32`: when outstanding debt is below the declared `amount` (or zero), `resolve_repay` returns the excess as `overpayment`, which is refunded via `transfer_out`.

`transfer_out` (contracts/pool/src/cache/cash.rs:46-53) moves `amount` of the market asset from the pool's own address to `recipient` and explicitly "does not adjust accounting cash". Neither refund path calls `debit_cash`. Crucially, neither the pool nor the controller verifies that `amount` was actually transferred in before the refund is sized - the doc comment "The controller transfers `amount` into the pool before this call" is a convention, not an enforced check. This is exactly the QV bug shape: the cached balance (`cash`) is not reduced by the payout, so the book diverges from custody after every refund.

### Impact Explanation
Two concrete impacts, both demonstrated by the repo's own tests:

1. **Theft of user funds.** A direct call `pool.recapitalize(key, attacker, custody)` with `amount` equal to the pool's token balance refunds the entire balance to the attacker (`test_unfunded_recapitalize_leaves_the_cash_book_overstating_custody` in contracts/pool/tests/flows.rs:3408-3433 drains the pool to zero). Likewise `repay` on a debt-free market treats the whole declared amount as overpayment and pays it out of custody (flows.rs:3590-3610). If the pool entrypoint only requires `payer.require_auth()`, the attacker simply uses their own address.
2. **Frozen user funds / phantom solvency.** After the drain, `cash` still credits suppliers' funds. Withdrawals and borrows pass `require_reserves` (cache/cash.rs:15-21, which reads the book, not the balance) and then revert inside the SAC transfer with `BalanceError = 10`, so legitimate suppliers cannot exit (flows.rs:3441-3477).

### Likelihood Explanation
Any unprivileged address can reach this path - `payer` is caller-chosen and authorizing it costs the attacker nothing. No funding is required: the refund is computed from the declared argument, so the entire attack is a single pool call with no capital. The only precondition is nonzero pool custody, which is the normal operating state. The repository's own test suite already exercises both variants (unfunded recapitalize and unfunded repay overpayment), confirming reachability without privileged roles.

### Recommendation
- In `ops::recapitalize::apply` and `ops::repay::apply`, debit `cash` by the refunded amount, or better, measure the actual inbound token delta (balance before/after the controller's transfer-in) and size `refund`/`overpayment` from the measured receipt rather than the declared `amount`.
- Alternatively, have the pool custody the refund only out of the just-received delta (e.g., re-measure balance and cap `refund` at `received - applied`), so a refund can never touch pre-existing supplier custody.
- Add an invariant check after refund legs asserting `cash == token.balance(pool)` (as `assert_cash_matches_balance` in tests/fuzz already does) or assert `refund <= actual received`.

### Proof of Concept
The repo already contains a working PoC in `contracts/pool/tests/flows.rs`:

```rust
// contracts/pool/tests/flows.rs:3408-3449 (abridged)
token_admin.mint(&t.pool, &deposit);            // supplier custody in pool
let custody = token.balance(&t.pool);
t.client().recapitalize(&hub(&t.asset), &payer, &custody);  // nothing transferred in
assert_eq!(token.balance(&t.pool), 0);          // custody fully drained to `payer`
assert!(t.state_snapshot().cash >= deposit);    // cash book still reports the funds

// Subsequent supplier withdraw passes require_reserves but reverts in the SAC:
let outcome = t.client().try_withdraw(&receiver, &false, &t.wdr(supplied, i128::MAX, 0));
// -> SAC BalanceError = 10, supplier receives nothing
```

And the repay variant at flows.rs:3590-3610: `repay(&payer, action(amount = custody))` on a market with zero debt credits nothing, refunds the full declared amount out of real custody, and leaves `cash` untouched.