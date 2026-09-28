The pool test comment hints at a real analog: `repay`'s overpayment refund pays out of custody without inbound funding. Let me verify the code path.### Title
Unfunded `repay` overpayment is refunded out of pool custody to any caller - (File: contracts/pool/src/ops/repay.rs)

### Summary
The pool's `repay` leg refunds the "overpayment" — the declared amount minus outstanding debt — directly to `payer` via `Cache::transfer_out`, without verifying that any tokens were actually transferred in, and without debiting `cash` or checking `require_reserves`. On a market with zero outstanding debt, the entire declared amount is treated as overpayment, so a single unprivileged `repay` call pays the attacker out of real supplier custody — the same bug class as D3Proxy's permissionless `refundETH` ("anyone can claim the contract's balance").

### Finding Description
`ops::repay::apply` calls `accounting`, then unconditionally transfers `outcome.overpayment` to `payer` at `contracts/pool/src/ops/repay.rs:32`. In `accounting`, `cache.resolve_repay(amount, position)` splits the declared `action.amount` into burned debt shares and `overpayment` (`contracts/pool/src/ops/repay.rs:44`). When the market's `current_debt_ceil` is zero, `resolve_repay` takes the full-close branch: `net_repay` is zero and `overpayment == amount`. The `RepayRoundsToZeroShares` assert at `contracts/pool/src/ops/repay.rs:48-52` explicitly passes on the `net_repay == 0` disjunct, so nothing reverts. The refund transfer is drawn from the pool's token balance but is never matched against an inbound transfer — the doc comment at `contracts/pool/src/ops/repay.rs:3` states the controller "transfers the repay amount into the pool before this call", yet the pool performs no measured-receipt check to enforce it (contrast with the controller side, which uses `transfer_amount_measured` and `refund_controller_balance_delta` snapshots in `contracts/controller/src/payments.rs:41-52`).

The same gap exists in `ops::recapitalize::apply`, which refunds the excess over the shortfall from custody, but `recapitalize` is routed through the controller which prefunds the inbound leg, so `repay` is the directly reachable vector: the pool test `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` (`contracts/pool/tests/flows.rs:3589-3610`) calls `client().repay(&payer, &ract(0, custody_before))` from a fresh address with no prior transfer and confirms the full custody is drained while the book (`cash`, `borrowed`) is untouched.

### Impact Explanation
Theft of user funds. An attacker calls `repay` with `amount` equal to the pool's entire token balance on any market with zero outstanding debt (or `amount` exceeding debt on a borrowed market, refunding the difference). The refund pays out of supplier custody while crediting nothing, so suppliers' deposits are transferred to the attacker. Repeated across markets, this drains the pool to zero — protocol insolvency.

### Likelihood Explanation
High. The attack requires a single permissionless call with attacker-chosen `payer` and `amount` arguments; no position, collateral, oracle manipulation, or timing is needed. It only requires a market whose `current_debt_ceil` is zero — e.g., a newly created or fully repaid market that still holds supplied liquidity — or any market where `amount > debt` (the excess is refunded regardless).

### Recommendation
Make the overpayment refund balance-derived rather than declared-amount-derived: snapshot the pool's token balance before the leg (or measure the inbound receipt as the controller does in `repay_debt_from_controller` / `payments.rs`) and cap the refund at the actual inbound delta. Alternatively, require the pool entrypoint to be invoked only through the controller flow that prefunds custody, and treat any `overpayment` exceeding the measured receipt as a revert.

### Proof of Concept
```rust
// contracts/pool/tests/flows.rs:3589-3610 (existing test demonstrates the drain)
let t = TestSetup::new();                       // pool holds supplier custody, zero debt
let payer = Address::generate(&t.env);          // attacker controls no position
let custody_before = token.balance(&t.pool);

t.client()
    .repay(&payer, &t.ract(0, custody_before))  // declared amount == full custody
    .get_unchecked(0);

// token.balance(&payer) == custody_before; token.balance(&t.pool) == 0;
// state.cash and state.borrowed unchanged — refund paid purely from custody
```

- `resolve_repay` returns `overpayment == amount` when `current_debt_ceil == 0` (`contracts/pool/src/ops/repay.rs:44`).
- `net_repay == 0` disjunct lets the assert pass (`contracts/pool/src/ops/repay.rs:48-52`).
- `cache.transfer_out(payer, outcome.overpayment)` pays the attacker (`contracts/pool/src/ops/repay.rs:32`).
- No `cash` debit and no `require_reserves` guard on the refund path (test comment `contracts/pool/tests/flows.rs:3578-3588`).