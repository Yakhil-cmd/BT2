### Title
Unfunded `recapitalize` refunds "excess" out of pool custody without debiting the cash book, paying the same reserves twice — (File: contracts/pool/src/ops/recapitalize.rs)

### Summary
The pool's `recapitalize` leg measures the declared `amount` against the internal cash shortfall and pays the "excess" back to `payer` via `transfer_out`, but — exactly like the `repay` overpayment path — it never verifies that any tokens were actually transferred in, and it never debits the `cash` book for the refund it sends. The same custody is therefore released twice: once as real tokens to `payer`, and a second time as book cash still backing every supplier's claim. This is the in-code analog of the reported double-free: a resource (pool reserves) is released by the error-handling/excess-return path while the accounting still treats it as owned.

### Finding Description
`ops::recapitalize::apply` derives a refund as `declared_amount − shortfall` from the *declared* input amount, not from a measured balance delta, then calls `transfer_out(payer, excess)`. The refund is a pure payout:

- it does not pass `require_reserves`,
- it does not debit `cash`,
- the market bookkeeping commits a `cash` figure that still counts the tokens that just left.

The repository's own regression test proves the mechanics end to end at `contracts/pool/tests/flows.rs:3408-3483` (`test_unfunded_recapitalize_leaves_the_cash_book_overstating_custody`): calling `recapitalize(hub, payer, custody)` with **no tokens transferred in** drains the pool's entire token balance to `payer` (`token.balance(&t.pool) == 0` afterward) while `state.cash` still reports at least the previous deposit total. The companion test `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` (`flows.rs:3590-3611`) documents that `ops::repay::apply`'s overpayment refund (`contracts/pool/src/ops/repay.rs:25-34`, `transfer_out(payer, overpayment)` gated only by `resolve_repay` on a zero-debt market) has the identical defect shape. Both refunds are computed from caller-declared amounts rather than from `balance_delta_since`-style measured receipts, unlike the controller's inbound settlement (`contracts/controller/src/payments.rs:10-52`).

### Impact Explanation
Theft of user funds / protocol insolvency. Each `recapitalize` call whose declared `amount` exceeds the shortfall pays the difference out of supplier custody while the `cash` book keeps counting it, so a repeat caller can drain the pool to zero in one call (`amount = pool balance`) with the market still reporting itself solvent. Suppliers' subsequent withdraws pass `require_reserves` (which reads the overstated book) and then revert inside the SAC transfer — the test pins that the exit fails with the token contract's balance error, not a pool guard — permanently freezing all remaining supplier claims. Because `cash` is never decremented, no amount of interest accrual reconciles the divergence; the market is insolvent on first honest withdrawal.

### Likelihood Explanation
Whether an unprivileged address reaches this directly depends on the caller chain: `pool.recapitalize` is `#[only_owner]`-gated to the controller, so exploitation requires routing through the controller's `recapitalize` entrypoint (which is listed among the unprivileged-reachable paths). If the controller forwards a user-chosen `payer`/`amount` without first measuring that `payer` funded the pool — the same "declared vs. measured" gap the pool's own test exploits — a single unprivileged call suffices: pass `amount` equal to the pool balance, receive the entire custody as "excess," and leave every supplier frozen. The `repay` variant needs a market with zero debt, which any caller can create by repaying the last outstanding loan or targeting a freshly created, never-borrowed market, and is reachable through the ordinary `repay` leg whenever the controller passes a declared amount larger than the measured receipt.

### Recommendation
Settle both refund legs against measured receipts, not declared amounts:

1. In `ops::recapitalize::accounting`/`apply` and `ops::repay::apply`, compute the refundable excess as `min(declared_amount, measured_inbound_delta)` — snapshot the pool's token balance before the call and cap the refund at the actual increase, mirroring `transfer_amount_measured`/`balance_delta_since` used on the controller's inbound legs.
2. Alternatively, debit `cash` (and run `require_reserves`) for any outbound refund so the book can never overstate custody, and reject refunds that exceed the real pool balance.
3. Apply the same measured-receipt discipline to any other leg that derives a payout from a caller-declared inbound amount (liquidation excess refunds in `positions/liquidation/math.rs:140-147` already trim against debt, but the token-side refund must be bounded by what was actually received).

### Proof of Concept
Adapted from `contracts/pool/tests/flows.rs:3408-3483` — run through the controller's `recapitalize` surface (or `repay` on a zero-debt market) so the pool receives a declared `amount` with no accompanying transfer:

```rust
// Pool has `deposit` tokens of custody backing supplier claims.
let custody = token.balance(&t.pool);

// No transfer_in happens; the attacker just declares amount == custody.
t.client().recapitalize(&hub(&t.asset), &attacker, &custody);

assert_eq!(token.balance(&t.pool), 0);            // custody drained to attacker
assert!(t.state_snapshot().cash >= deposit);      // book still claims the funds

// The double-release: the same reserve was paid to the attacker AND still
// backs supplier claims. The first honest withdraw passes the liquidity
// guard (book says solvent) and reverts inside the SAC transfer.
let outcome = t.client().try_withdraw(&supplier, &false, &withdraw_all);
assert!(outcome.is_err()); // fails with SAC balance error, not a pool guard
```

For the `repay` variant (`flows.rs:3590-3611`): on a market with `borrowed == 0`, call `repay(payer, [(position=0, amount=custody)])`. `resolve_repay` treats the whole amount as overpayment, `net_repay == 0` satisfies the `RepayRoundsToZeroShares` disjunct, and `transfer_out(payer, amount)` pays the full custody out of the book-untouched reserves — the identical double-release of the same funds.