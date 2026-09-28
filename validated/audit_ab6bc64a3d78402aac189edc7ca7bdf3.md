### Title
Unverified repay/recapitalize refund pays out declared "excess" from real pool custody, draining the market - (File: contracts/pool/src/ops/repay.rs)

### Summary
`ops::repay::accounting` and `ops::recapitalize::accounting` compute a refund purely from the *declared* `action.amount`/`amount` argument and the market's internal books — never from the tokens the pool actually received. `ops::repay::apply` then executes `cache.transfer_out(payer, overpayment)` unconditionally. If the declared amount exceeds the real inbound transfer, the "overpayment" is paid out of the pool's pre-existing custody while `cash` is never debited for it — the book keeps reporting drained funds as present. This is the same bug class as the Dinari finding: a claim computed from stale/declared accounting rather than actual delivered escrow lets a caller withdraw funds the contract never received.

### Finding Description
In `contracts/pool/src/ops/repay.rs:44-57`, `resolve_repay(amount, position)` splits the declared `amount` into `burned` debt shares and `overpayment`; `net_repay = amount - overpayment` is credited to `cash`, and `apply` transfers `overpayment` to `payer` at line 32. No balance check ties `amount` to the pool's token balance before or after the call — the pool trusts the caller's declared figure. The same shape exists in `contracts/pool/src/ops/recapitalize.rs:52-58`, where `refund = amount - applied` is transferred to `payer` at line 34 without any custody verification.

The pool's own test suite proves the drain: `contracts/pool/tests/flows.rs:3578-3610` (`test_unfunded_repay_overpayment_refund_also_pays_out_of_custody`) documents that a repay against a debt-free market makes the entire declared amount an overpayment, refunded in full out of custody with `cash` untouched, and `flows.rs:3404-3406` notes that `Cache::require_reserves` reads the book, not the balance, so the market keeps reporting itself solvent while unable to pay subsequent withdrawals.

The pool entrypoints are `#[only_owner]` (the controller), so reachability flows through controller `repay`/`recapitalize` calls (`contracts/pool/src/lib.rs:168,187`). The pool contract's defense comment — "The controller transfers the repay amount into the pool before this call" — is a cross-contract assumption, not an enforced invariant: the pool never measures `balance_delta` the way the controller does in `payments.rs::refund_controller_balance_delta`. Any controller path that forwards a declared amount without first delivering the full tokens (e.g., a leg settled by accounting credit rather than token transfer, or a future/refactored leg) immediately converts into a custody drain payable to a caller-chosen `payer`.

### Impact Explanation
Theft of user funds / protocol insolvency: the refund transfer draws down the pool's real token balance while `cash` (the solvency book) is unchanged. Suppliers' later withdrawals then pass `require_reserves` on overstated books and fail at the SAC transfer, or silently pay out remaining custody to early withdrawers — first-come-first-served loss socialization identical to Dinari's drained `paymentToken` escrow.

### Likelihood Explanation
Medium. The primitive is proven by the pool's own tests. Exploitation requires a reachable path where the declared amount exceeds delivered tokens; the pool offers no defense and relies entirely on the controller's funding discipline, which the refund-paying legs (`repay`, `recapitalize`) do not verify.

### Recommendation
Measure receipts instead of trusting declarations: snapshot the pool's token balance before the leg and cap `overpayment`/`refund` at the actual `balance_delta`, or have `transfer_out` for refunds pass through `require_reserves`/debit `cash` so refunded funds are accounted as leaving custody. Alternatively, assert inside `repay`/`recapitalize` that `balance(token) >= cash` after accounting, before transferring.

### Proof of Concept
```rust
// Mirrors contracts/pool/tests/flows.rs:3590
// Market holds custody_before tokens; no debt outstanding.
let custody_before = token.balance(&t.pool);
// Declared amount equals full custody; nothing is actually transferred in
// beyond what the leg delivers. With no debt, resolve_repay classifies the
// entire amount as overpayment.
let credited = pool.repay(&payer, &actions(amount = custody_before))[0].actual_amount;
assert_eq!(credited, 0);                    // no debt retired, cash unchanged
assert_eq!(token.balance(&payer), custody_before); // payer walked off with custody
assert_eq!(token.balance(&t.pool), 0);
// cash still reports custody_before -> future withdraws pass require_reserves
// and then fail at the token transfer.
```

Note: full end-to-end reachability depends on whether every controller repay/recapitalize path pre-funds the declared amount — I verified the pool-side root cause and its test proof, but did not exhaustively confirm a controller path that forwards an unfunded declared amount within the available iterations. If all controller legs always transfer `amount` in first, this degrades to a defense-in-depth gap rather than a live exploit.