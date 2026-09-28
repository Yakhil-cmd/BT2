### Title
Repay overpayment refund is derived from the declared amount and paid out of token custody without debiting the cash book or checking reserves — (File: contracts/pool/src/ops/repay.rs)

### Summary
The kernel bug rejects only clones whose declared length exceeds `PAGE_SIZE`, ignoring the extra `skb_shared_info` tailroom a downstream stage requires — so an input that passes the naive bound still overruns reserved space. The pool's repay leg has the same shape: `resolve_repay` computes `overpayment = amount − debt` purely from the *declared* `action.amount`, then `apply` transfers that overpayment out of the pool's real token balance via `Cache::transfer_out`. The refund leg neither debits `cash` nor calls `require_reserves`, so the "tailroom" the book-keeping assumes (that the declared amount was actually transferred in first) is never enforced. A repay against a market with little or no debt refunds almost the entire declared amount straight out of supplier custody.

### Finding Description
- `ops::repay::accounting` resolves `overpayment` from the caller-declared `action.amount`, credits only `net_repay = amount − overpayment` to cash, and commits. (`contracts/pool/src/ops/repay.rs:40-66`)
- `ops::repay::apply` then executes `outcome.cache.transfer_out(payer, outcome.overpayment)`. (`contracts/pool/src/ops/repay.rs:25-34`)
- `Cache::transfer_out` performs a raw `token::Client::transfer` from the pool address and explicitly "does not adjust accounting cash"; `require_reserves` is only applied inside `debit_cash`, which this leg never calls. (`contracts/pool/src/cache/cash.rs:14-21`, `:46-53`)
- The only guard is `RepayRoundsToZeroShares`, which is satisfied vacuously when `net_repay == 0` — i.e., the pure-refund case. (`contracts/pool/src/ops/repay.rs:48-52`)
- The same unfunded-refund pattern exists in `ops/recapitalize::apply` (excess over the shortfall), per the in-repo analysis comment. (`contracts/pool/tests/flows.rs:3578-3588`)

### Impact Explanation
Theft of user funds / contract unable to operate. The in-repo test `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` demonstrates it: with zero debt and zero inbound transfer, `repay(payer, amount = custody_before)` credits `0`, yet `transfer_out` moves the entire declared amount — equal to the pool's whole token balance — to `payer`, draining supplier custody while the `cash` book still reports the pre-attack value. (`contracts/pool/tests/flows.rs:3589-3611`) Subsequent withdraws/borrows then fail on `InsufficientLiquidity` or pay out of a phantom book, freezing the market. Even where debt exists, only `debt` is gated; the `amount − debt` headroom is attacker-controlled.

### Likelihood Explanation
Reachable by a single unprivileged address through the repay path: the pool test invokes `client().repay(&payer, &action)` directly with an attacker-chosen `amount`, and the refund recipient `payer` is a caller-supplied argument. The exploit requires no position, no collateral, and no actual token transfer in — the refund is computed from the declared amount, not a measured balance delta. The one uncertainty I could not fully resolve is whether production callers reach this only via `controller.repay` (which may pull funds first); the pool-side leg itself contains no such enforcement, and the harness proves the drain on the pool entrypoint. If `repay` is restricted to the controller, the identical primitive remains exploitable wherever a declared repay amount can exceed the real transfer-in (e.g., liquidation or strategy legs that trust the declared amount).

### Recommendation
Apply the same fix pattern as the kernel: check against the true reserved bound, not the naive one.
- In `ops::repay::apply`/`accounting`, route the refund through `debit_cash(overpayment)` (or at minimum `require_reserves(overpayment)`) so the refund is funded by accounted cash, exactly as `SKB_WITH_OVERHEAD` enforces the tailroom.
- Better: derive `overpayment` from the *measured* inbound balance delta (`balance_after − balance_before − net_repay`) instead of the declared `action.amount`, matching the protocol's measured-receipt settlement used elsewhere.
- Apply the identical fix to the excess refund in `ops/recapitalize::apply`.

### Proof of Concept
```rust
// Mirrors contracts/pool/tests/flows.rs:3589-3611
// Setup: market with suppliers, zero outstanding debt.
let t = TestSetup::new();
let token = token::Client::new(&t.env, &t.asset);
let attacker = Address::generate(&t.env);

let custody_before = token.balance(&t.pool);   // e.g. all supplier deposits
// Declare amount == full custody; nothing is transferred in, no debt exists.
let credited = t
    .client()
    .repay(&attacker, &t.ract(0, custody_before))
    .get_unchecked(0)
    .actual_amount;

assert_eq!(credited, 0);                                  // book untouched
assert_eq!(token.balance(&t.pool), 0);                    // custody drained
assert_eq!(token.balance(&attacker), custody_before);     // attacker paid
```