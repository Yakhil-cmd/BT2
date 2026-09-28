### Title
`repay` and `recapitalize` refund a declared overpayment that was never transferred in, draining pool custody - ([File: contracts/pool/src/ops/repay.rs])

### Summary
The pool's `repay` leg computes the overpayment refund purely from the *declared* `action.amount` and the position's outstanding debt, then transfers the excess back to the payer via `cache.transfer_out(payer, outcome.overpayment)`. Nothing in the leg verifies that `amount` tokens were actually received; the refund is paid out of real token custody. The same shape exists in `recapitalize`, where `refund = amount - applied` is transferred to the payer. This is the direct analog of CVE-2024-26980: a size check (debt vs. request) is resolved against the declared request size, while the actual input backing that size is never validated — the "transform" path where validation is skipped.

### Finding Description
In `contracts/pool/src/ops/repay.rs`:

```rust
let (burned, overpayment) = cache.resolve_repay(amount, position);
let net_repay = amount.checked_sub(overpayment)...;
cache.credit_cash(net_repay);
...
outcome.cache.transfer_out(payer, outcome.overpayment);
```

`resolve_repay` returns `overpayment = max(0, amount - current_debt_ceil)`. When the market carries no debt (debt ceiling is zero), the **entire** declared `amount` becomes `overpayment`, `net_repay` is zero, the `RepayRoundsToZeroShares` assert passes on its `net_repay == 0` disjunct, and `transfer_out` sends the declared amount to the payer from the pool's real balance. The code comment "The controller transfers the repay amount into the pool before this call" is an assumption, not an enforced precondition — the pool does not measure a balance delta.

`recapitalize::apply` has the identical hole: `applied = amount.min(backing_shortfall)` and `refund = amount - applied` is transferred out. With zero backing shortfall, the full declared `amount` is refunded.

The in-repo test `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` (`contracts/pool/tests/flows.rs:3589`) pins this: `repay(payer, custody_before)` with nothing transferred in and no debt drains the pool's entire custody into the payer's refund.

### Impact Explanation
Theft of user funds. If the `repay`/`recapitalize` pool entrypoints (or any controller path that reaches them without an enforced prior transfer, e.g. a measured-receipt leg that records less than the declared amount) can be invoked by an unprivileged address, the attacker declares `amount = pool token balance`, receives it back as a "refund," and walks away with supplier funds — protocol insolvency in a single call. Even through the controller, any leg where the measured inbound transfer can be less than the declared amount converts the difference into a payout from other users' deposits.

### Likelihood Explanation
High if the pool leg is reachable without a controller-enforced transfer; the test demonstrates the drain works end-to-end against a funded market with a single `repay` call. The precondition relies on an off-contract invariant (controller ordering) rather than in-contract verification (balance delta), so any alternate caller, batching path, or receipt-measurement discrepancy reaches it.

### Recommendation
Validate against measured input, not declared input — the same fix shape as the CVE (validate after decryption instead of trusting the pre-transform header). Either:
- Snapshot the pool token balance before/after the expected inbound transfer and cap `overpayment`/`refund` at the measured delta, or
- Enforce at the pool boundary that `repay`/`recapitalize`/`net_settle` can only be invoked by the controller within a transaction that provably transferred `amount` first (e.g., measured-receipt settlement that ties `amount` to `balance_after - balance_before`).

### Proof of Concept
Already encoded in the repo's own test (`contracts/pool/tests/flows.rs:3590`):

```rust
let custody_before = token.balance(&t.pool);
// Nothing transferred in, no debt to retire: the whole amount is "excess".
let credited = t.client().repay(&payer, &t.ract(0, custody_before))
    .get_unchecked(0).actual_amount;
assert_eq!(credited, 0);
assert_unfunded_refund_drained_custody(&t, &payer, custody_before, &before);
```

A fresh market with supplier cash, zero borrows, and a `repay` of `amount = cash` pays the full pool balance to the payer as overpayment, leaving the book untouched and suppliers unbacked.