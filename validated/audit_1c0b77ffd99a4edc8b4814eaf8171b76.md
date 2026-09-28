### Title
Unfunded overpayment refund drains pool custody via declared-amount subtraction - (File: contracts/pool/src/ops/repay.rs, contracts/pool/src/ops/recapitalize.rs)

### Summary
The libssh2 bug subtracts attacker-influenced lengths and uses the result unchecked. The analog here: `repay` and `recapitalize` compute a refund as `declared_amount − applied` where `declared_amount` is caller-chosen, then pay that refund out of the pool's real token custody — without verifying that any tokens were actually transferred in. When the applied portion is small or zero (no debt, no backing shortfall), nearly the entire declared amount becomes "excess" and is refunded to the caller for free.

### Finding Description
In `repay::accounting` (`contracts/pool/src/ops/repay.rs:44-47`), `resolve_repay` caps the burned debt at the position's outstanding debt and returns the remainder as `overpayment`; `apply` then calls `outcome.cache.transfer_out(payer, outcome.overpayment)` at line 32, a real token transfer out of pool custody. The doc comment at line 3 states "The controller transfers the repay amount into the pool before this call" — i.e., funding is assumed, never measured. `credit_cash` is only called with `net_repay` (line 57), so the refund leg never debits `cash` and never passes `require_reserves`; it draws directly on the token balance.

`recapitalize::accounting` (`contracts/pool/src/ops/recapitalize.rs:52-55`) is identical in shape: `applied = amount.min(backing_shortfall)`, `refund = amount - applied`, then `apply` transfers `refund` to `payer` at line 34.

`transfer_out` (`contracts/pool/src/cache/cash.rs:46-52`) sends real tokens with only a non-negative check. On a market with zero debt, `resolve_repay` takes the full-close branch, `net_repay` is zero, and the entire declared `amount` is refunded out of custody.

### Impact Explanation
Theft of user funds / permanent freezing. A caller declares `repay` or `recapitalize` amount equal to the pool's full token balance on a market with no debt or no shortfall; the contract refunds the entire declared amount to the caller while crediting nothing to the book. Custody drops to zero while the `cash` book still reports full reserves, so subsequent legitimate `withdraw`/`borrow` calls pass `require_reserves` (which reads the book) and then fail inside the SAC transfer — honest suppliers' funds are stolen and exits are frozen. Both behaviors are demonstrated by the codebase's own tests: `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` (`contracts/pool/tests/flows.rs:3590-3610`, refunding `custody_before` with zero transfer-in) and `test_unfunded_recapitalize_leaves_the_cash_book_overstating_custody` (`contracts/pool/tests/flows.rs:3408-3482`, custody drained to 0, withdraw then fails with SAC `BalanceError`).

### Likelihood Explanation
If the pool's `repay`/`recapitalize` entrypoints are reachable by any address (or reachable through a controller path where the caller does not pre-fund the declared amount), the attack is a single transaction: declare `amount = pool balance`, receive `amount` back. The exploit primitive — declared-amount refund without measured inbound receipt — exists unconditionally; the open question is whether deployed auth restricts these pool calls to the controller, in which case exposure depends on whether every controller path that invokes them actually transfers the declared amount first. The unit tests invoke `client().repay(&payer, ...)` and `client().recapitalize(&hub, &payer, &amount)` directly with an unfunded payer and succeed, indicating the pool itself does not pull or measure the inbound transfer.

### Recommendation
Measure receipt instead of trusting the declared amount: snapshot the pool's token balance before/after the inbound leg (as `balance_delta_since` in `contracts/controller/src/payments.rs:10-20` already does for the controller), and cap `overpayment`/`refund` at the measured receipt, e.g. `refund = min(amount - applied, received)`. Alternatively, make the pool pull `amount` itself via `transfer_from`/auth before computing the refund, or restrict these entrypoints to the controller and have the controller settle refunds only from its measured delta (`refund_controller_balance_delta`, `payments.rs:41-52`).

### Proof of Concept
```rust
// Modeled on contracts/pool/tests/flows.rs:3590-3610
// Market with supply, zero debt. Attacker sends nothing.
let custody = token.balance(&t.pool);              // e.g. 10_000_000_000
// repay(amount = custody) on a debt-free market:
//   resolve_repay -> net_repay = 0, overpayment = custody
//   apply -> transfer_out(payer=attacker, custody)
client.repay(&attacker, &t.ract(0, custody));
// attacker now holds `custody`; token.balance(&pool) == 0
// state.cash still reports reserves; supplier withdraws fail in SAC transfer
```
Same shape via `recapitalize` on a market with `backing_shortfall == 0`: `applied = 0`, `refund = amount`, entire pool balance paid out.