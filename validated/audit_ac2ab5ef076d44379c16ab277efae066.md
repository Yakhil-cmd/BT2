### Title
`recapitalize` pays a refund and credits cash against a declared `amount` without verifying tokens were received, letting an unprivileged caller drain pool custody and overstate the cash book - (File: contracts/pool/src/ops/recapitalize.rs)

### Summary
`Pool::recapitalize` credits `min(amount, backing_shortfall)` to the accounting cash book and transfers `amount - applied` back to the `payer` from the pool's own token balance. The declared `amount` is treated as already-delivered custody: nothing inside `accounting` measures or checks an actual inbound transfer, and `transfer_out` pays the refund unconditionally while leaving the cash book untouched. This is the direct analog of "unchecked return / missing validation before dereference": a value that can be wrong (the pretended deposit) is consumed as if it were real.

### Finding Description
In `contracts/pool/src/ops/recapitalize.rs`, `accounting` computes:

```rust
let applied = amount.min(guards::backing_shortfall(&cache));
let refund = amount.checked_sub(applied)...;
cache.credit_cash(applied);
cache.commit();
```

then `apply` executes `outcome.cache.transfer_out(&payer, outcome.refund)`.

Two consequences follow when the caller never funded the pool:

1. **Refund drain**: `refund = amount - applied` is paid out of pool custody to `payer`. Choosing `amount = applied + pool_balance` makes the refund equal to the pool's entire token balance. The repo's own test `test_unfunded_recapitalize_leaves_the_cash_book_overstating_custody` in `contracts/pool/tests/flows.rs:3408-3483` demonstrates exactly this — `recapitalize(&hub, &payer, &custody)` leaves `token.balance(&pool) == 0` with no deposit having occurred.
2. **Book/custody divergence**: `credit_cash(applied)` writes the cash book as if reserves were restored. The same test shows that after the drain, `state.cash >= deposit`, so `require_reserves` in `contracts/pool/src/cache/cash.rs:15-21` passes on the stale book and supplier withdrawals then fail inside the SAC transfer (`BalanceError = 10`), not at any pool guard.

`Cache::transfer_out` (`contracts/pool/src/cache/cash.rs:46-53`) performs a raw `token.transfer` with no book debit, so the refund is pure outflow against suppliers' custody.

### Impact Explanation
If `recapitalize` is reachable without funding verification on the controller path (i.e., `payer` is an arbitrary caller argument and the pool does not measure the inbound delta), an unprivileged address can:
- extract up to the pool's full token balance as a "refund" for tokens it never sent — theft of supplier funds; and/or
- inflate `state.cash` by `applied` without custody, leaving the market reporting solvency while withdrawals revert in the token contract — temporary/permanent freezing of supplier funds.

Both are accepted impact classes (theft of user funds; temporary freezing of funds). If the deployed controller enforces that only a measured `transfer_amount_measured` result is passed as `amount` and pool `recapitalize` is gated to the controller, the residual issue is the uncorrected book overstatement shown in the test — still a fund-freezing defect when custody is short.

### Likelihood Explanation
The trigger requires a market with `backing_shortfall > 0` (produced by bad-debt events) or an arbitrary large `amount` for the refund-drain variant, plus a reachable `recapitalize` call. No privileged keys, no leaked data, no external oracle cooperation, and no timing condition is needed: the arithmetic is deterministic and the pool pays the refund from its own balance. Whether the endpoint is directly callable or only via the controller determines whether this is theft (pool-level call) or bookkeeping corruption (controller passes measured amounts); the code itself performs no receipt check either way.

### Recommendation
Measure the actual inbound delta inside `apply`/`accounting` (e.g., `token.balance(pool)` before vs. after a pull, or have the controller pass the `transfer_amount_measured` result and authenticate the caller), and compute `applied`/`refund` from that measured figure rather than the declared `amount`. Alternatively, restrict `recapitalize` to the controller and assert `cash` never exceeds actual custody, and refuse `refund > 0` when the pool was not funded in the same transaction.

### Proof of Concept
Adapted from the repo's own test at `contracts/pool/tests/flows.rs:3408-3483`:

```rust
// Supplier deposits; book and custody agree.
token_admin.mint(&pool, &deposit);
client.supply(&sup(0, deposit));

// Unprivileged caller, zero funding moved in:
let custody = token.balance(&pool);
client.recapitalize(&hub(&asset), &attacker, &custody);
// If shortfall == 0: applied = 0, refund = custody -> attacker balance += custody,
// pool balance == 0, while state.cash still >= deposit.

// Supplier withdraw passes require_reserves (book reads solvent)
// then fails inside the SAC transfer with BalanceError(10).
let outcome = client.try_withdraw(&receiver, &false, &wdr(supplied, i128::MAX, 0));
assert!(outcome.is_err());
```

With `backing_shortfall > 0`, calling `recapitalize(hub, attacker, shortfall + custody)` yields `applied = shortfall` (book credited as recapitalized) and `refund = custody` paid to the attacker — simultaneous solvency forgery and custody drain, neither gated by any receipt check in `accounting`.