### Title
Unfunded repay/recapitalize overpayment refund drains pool custody - (File: contracts/pool/src/ops/repay.rs)

### Summary
`ops::repay::apply` and `ops::recapitalize::apply` compute the "excess" refund from the **declared** `action.amount` / `amount` argument — the analog of the OpenSSL two-pass bug where a stale source-length is trusted as destination capacity — rather than from tokens actually received. When the declared amount exceeds the real obligation (debt or backing shortfall), the difference is transferred out of the pool's real custody to the caller even if the caller never transferred anything in.

### Finding Description
In `contracts/pool/src/ops/repay.rs:25-67`, `apply` calls `accounting`, which resolves `overpayment = max(0, amount - actual_debt)` via `cache.resolve_repay(amount, position)` and then executes `outcome.cache.transfer_out(payer, outcome.overpayment)` at line 32. `transfer_out` moves real tokens from pool custody; the refund is derived entirely from the caller-supplied `amount`, not from a measured balance delta.

Similarly, `contracts/pool/src/ops/recapitalize.rs:26-67` sets `applied = min(amount, backing_shortfall)` and `refund = amount - applied`, then `transfer_out(&payer, refund)` at line 34 — again paying from custody based on a declared amount.

The repo's own regression test proves the exploit path: `contracts/pool/tests/flows.rs:3589-3611` (`test_unfunded_repay_overpayment_refund_also_pays_out_of_custody`) calls `pool.repay(&payer, &ract(0, custody_before))` on a market with zero debt and no inbound transfer, and asserts custody is drained by the full declared amount (`assert_unfunded_refund_drained_custody`). The comment at lines 3578-3588 explicitly states neither refund "debits `cash` or passes `require_reserves`".

### Impact Explanation
An unprivileged address calls `repay` (or `recapitalize`) on a market with zero/shortfall-bounded obligations, declares `amount = pool token balance`, transfers nothing in, and receives the full "overpayment" — direct theft of supplier funds held in pool custody. If a controller auth gate exists on `repay`, the same shape is reachable via `recapitalize`, which the rules list as in-scope, or via a liquidation `offered` leg where `apply_liquidation_repayments` pulls the merged offered amount but the pool-side refund math still keys off declared vs actual debt.

### Likelihood Explanation
Single transaction, no privileges, no timing dependence. The only precondition is a market whose outstanding debt or backing shortfall is smaller than the pool's token balance — trivially satisfiable, including a freshly listed market with suppliers but no borrows.

### Recommendation
Measure the inbound leg: snapshot the pool's token balance before crediting and compute `received = balance_after_in - balance_before` (as `transfer_amount_measured` in `contracts/controller/src/positions/liquidation/apply.rs:58` already does for the pull side), then cap `overpayment`/`refund` at `received`. Alternatively, gate the refund on `net_repay == min(amount, obligation)` against measured cash rather than declared `amount`.

### Proof of Concept
```rust
// Mirror of contracts/pool/tests/flows.rs:3589-3611
let t = TestSetup::new();                       // market has suppliers, zero debt
let token = token::Client::new(&t.env, &t.asset);
let attacker = Address::generate(&t.env);       // holds no tokens
let custody = token.balance(&t.pool);           // e.g., 1_000_000e7

// No transfer in; declared amount = entire custody.
t.client().repay(&attacker, &t.ract(0, custody));

assert_eq!(token.balance(&attacker), custody);  // drained via refund
assert_eq!(token.balance(&t.pool), 0);
```

The existing test `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` already asserts this drains custody; it is currently framed as a "refund gap" observation rather than gated. Caveat: if `pool::repay` enforces controller-only auth, the same defect must be exercised through `recapitalize`, which performs the identical declared-vs-applied refund at `recapitalize.rs:52-55` and is an in-scope unprivileged entrypoint.