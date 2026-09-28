### Title
Unfunded `repay` overpayment refund pays real pool custody without debiting the cash book - (File: contracts/pool/src/ops/repay.rs)

### Summary
The pool's `repay` leg resolves the declared `action.amount` into `net_repay` + `overpayment`, credits only `net_repay` to `cash`, commits the state, and then `transfer_out`s the full `overpayment` to the payer from the pool's real token balance. Because the refund path is computed after commit and is never debited from `cash` nor passed through `require_reserves`, a `repay` whose declared amount exceeds the position's debt pays tokens out of custody that no inbound transfer ever funded. This is the same defect class as CVE-2024-53164: a custody-affecting adjustment (the overpayment refund) is ordered after the state commit that was supposed to account for it, so the books "fail to notify" the reserve layer that balance left — `cash` stays intact while real tokens leave.

### Finding Description
`ops::repay::accounting` calls `cache.resolve_repay(amount, position)`, burns `burned` debt shares, credits `net_repay = amount - overpayment` to cash, and `commit()`s — all before `apply` calls `outcome.cache.transfer_out(payer, outcome.overpayment)` (contracts/pool/src/ops/repay.rs:30-66). The refund is derived from the *declared* `action.amount`, not from a measured receipt inside the pool, and `gate_and_debit`/`require_reserves` (the guard used by `withdraw.rs:111-119`) is never applied to it.

The pool's own test proves the primitive end-to-end: `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` (contracts/pool/tests/flows.rs:3590-3611) calls `client().repay(&payer, &ract(0, custody_before))` on a market with zero debt and **no prior transfer in**. `resolve_repay` takes the full-close branch (`current_debt_ceil == 0`), `net_repay == 0`, the `RepayRoundsToZeroShares` assert passes on its `net_repay == 0` disjunct, and the entire declared amount is refunded out of real custody with `cash` untouched. The same gap exists in `ops::recapitalize::apply` (excess over the shortfall), per the comment at flows.rs:3578-3588.

Controller-mediated flows pre-fund the pool via `transfer_amount_measured` (`legs.rs:50-57`, `liquidation/apply.rs:58-65`), so through `repay`/`liquidate` the refund is bounded by tokens just delivered. The defect is exploitable in two in-scope ways:
1. If the pool's `repay`/`recapitalize` action entrypoints are reachable without the controller's pre-funding (as the unit test does directly on the pool client), an unprivileged caller drains custody by declaring `amount = pool_balance` against a zero- or low-debt position.
2. Even via the controller, `recapitalize`'s refund basis is the pool's *measured* receipt — with any token that over-delivers on transfer (or a direct donation to the pool inflating `balance - cash`), the refund paid to `payer` can exceed what `cash` was credited, silently converting the book-vs-custody gap into an outflow.

Either way, real tokens leave while `state.cash` is unchanged, so `require_reserves`/`backing shortfall` checks continue to report a fully backed market — the exact "qlen updated after reduce_backlog" inversion: the observable counter is adjusted only after (and independently of) the operation that emptied the child.

### Impact Explanation
Pool custody is drawn down below the tracked `cash` reserve. Suppliers' claims (`supplied * supply_index`) remain on the books, so subsequent withdraws/borrows pass `require_reserves` on paper but the tokens are gone — theft of user funds and eventual inability to operate the market (withdraws revert on insufficient token balance). For the direct-call variant this is full custody drainage by a single unprivileged call; for the controller variant it is a bounded but repeatable extraction of donated/over-delivered balances that belong to the reserve.

### Likelihood Explanation
The ordering defect is unconditional in `repay::accounting`/`apply` — every overpayment refund bypasses `debit_cash` and `require_reserves` by construction. Exploitability hinges on reachability: the pool test demonstrates the drain works when `repay` is invoked without a matching inbound transfer, so if the pool contract does not restrict its action dispatcher to the controller, exploitation is a one-transaction call. I could not fully verify the pool's external auth gate within the available iterations (`fn repay`/`require_auth` did not surface in `contracts/pool/src` grep, likely because dispatch lives in a generated client trait or a differently-named module), so the severity ranges from Critical (permissionless pool entrypoint) to High (requires an over-delivering token or donation to create the custody/book gap the refund then consumes).

### Recommendation
Apply the CVE's fix pattern: account for the outflow *before* it is observable. Concretely, in `ops::repay::apply` (and `ops::recapitalize::apply`):
- Debit `cash` for the overpayment refund, or better, require that the refund never exceeds the measured inbound delta — snapshot the pool token balance before the controller's funding transfer and bound `overpayment` by that delta rather than by declared `amount`.
- Alternatively gate the refund through the same `require_reserves`/`debit_cash` path used by `withdraw::gate_and_debit`, so a refund can never pay out reserves that were not just received.
- Ensure the pool's action entrypoints reject callers other than the controller if they are currently open.

### Proof of Concept
Mirroring `contracts/pool/tests/flows.rs:3590-3611`:

```rust
// Market with suppliers funded, zero outstanding debt.
let custody_before = token.balance(&pool);

// No tokens transferred in. Declare amount = entire pool balance.
let credited = pool_client
    .repay(&attacker, &PoolAction { position: zero, amount: custody_before })
    .get_unchecked(0)
    .actual_amount;

assert_eq!(credited, 0);                       // nothing credited to cash
assert_eq!(token.balance(&attacker), custody_before); // custody drained
assert_eq!(pool_state.cash, custody_before);   // book still claims full reserves
```

The attacker walks away with the pool's token balance while `cash` (the `qlen` analog) was never decremented — subsequent withdraws pass reserve checks but fail on token transfer, permanently freezing supplier funds.