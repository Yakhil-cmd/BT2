### Title
`recapitalize` credits booked cash and refunds `amount - applied` from custody without measuring actual tokens received, leaving `cash` book overstating holdings and breaking withdrawals — ([File: contracts/pool/src/ops/recapitalize.rs])

### Summary
This is the XOXNO Lending analog of Olympus's `getReserveBalance()` bug: the pool's liquidity/solvency checks read an accounting book (`cash`), not the actual token balance, and an unprivileged-reachable path (`recapitalize`) can make the book claim funds that were never deposited. The pool's `recapitalize` does not measure the balance delta of the transfer-in (despite `INV-ACCT-03` claiming "measured receipt"); it blindly credits `min(amount, shortfall)` to cash and pays out `amount - applied` as a "refund" to the `payer`. A caller who invokes `recapitalize` with a large `amount` on a market with little or no backing shortfall receives a refund of real custodied tokens it never sent, while the `cash` book still shows those funds as present — so later `withdraw`/`borrow` calls pass `require_reserves` and then fail inside the SAC `transfer`, exactly like `Operator.swap()` failing in the Olympus report.

### Finding Description
In `recapitalize::accounting`, `applied = amount.min(backing_shortfall(&cache))` is credited to `cash` unconditionally (`cache.credit_cash(applied)`), and `apply` then executes `outcome.cache.transfer_out(&payer, outcome.refund)` where `refund = amount - applied`. There is no `token::Client::balance` snapshot before/after, unlike the measured-receipt paths documented in `INV-ACCT-03`. The accompanying test `test_unfunded_recapitalize_leaves_the_cash_book_overstating_custody` (contracts/pool/tests/flows.rs:3408) demonstrates the end state: a direct `recapitalize(&hub, &payer, &custody)` call with no funding drains the entire pool balance to `payer` while `state.cash` still reports `>= deposit`, and a supplier's subsequent `withdraw` clears `require_reserves` (cash.rs:15-21, which checks `self.cash >= amount`, not `token.balance(pool)`) and then aborts with the SAC insufficient-balance error.

The preconditions for the drain are minimal: any market state where `backing_shortfall < amount` — trivially satisfied on a healthy market where the shortfall is 0, since `applied = min(amount, 0) = 0` and `refund = amount`. Direct token transfers to the pool and `recapitalize` are both in the unprivileged attack surface, so the caller can stage the call through the controller's `recapitalize` entrypoint with a `payer` it controls.

### Impact Explanation
Theft of user funds / protocol insolvency. The refund leg transfers real custodied tokens to an attacker-controlled `payer` for tokens never received, directly draining supplier deposits. Even if partially exploited, the residual state leaves `cash` book > actual balance, so legitimate suppliers' `withdraw` calls pass the pool's own liquidity guard and revert inside the token transfer — the same "book says solvent, contract cannot pay" breakage as the Olympus treasury.

### Likelihood Explanation
The pool-side implementation contains no receipt measurement and no guard tying `refund` to observed balance deltas; the repository's own test proves a single unfunded `recapitalize` call drains 100% of custody. Reachability depends on the controller's `recapitalize` path forwarding the call for an arbitrary payer without itself enforcing the transfer-in, which the in-scope surface list and the pool's trust assumption ("The controller transfers `amount` into the pool before this call" — recapitalize.rs:4) indicate is the intended usage. The assumption is enforced nowhere in the pool.

### Recommendation
Make `recapitalize` use measured receipt: snapshot `token.balance(pool)` before crediting, require the controller's transfer to have occurred (or pull the tokens inside the same call), credit `applied = min(measured_receipt, shortfall)`, and cap `refund` at `measured_receipt - applied`. Additionally, consider having `require_reserves` validate against `min(cash, actual_balance)` so the book can never authorize exits the contract cannot pay.

### Proof of Concept
1. Healthy market: supplier deposits D via `supply` → `cash = D`, pool balance = D, `backing_shortfall = 0`.
2. Attacker calls `recapitalize(hub_asset, attacker, D)` with **no** prior token transfer.
3. `applied = min(D, 0) = 0`, `refund = D` → `transfer_out(attacker, D)` moves all custodied tokens to the attacker.
4. Pool balance = 0; `cash` book still = D (or more).
5. Supplier calls `withdraw(receiver, i128::MAX)`: `require_reserves(D)` passes against the book, then `transfer_out` reverts with SAC `BalanceError(10)`. Supplier funds are gone; the market reports itself solvent.

This exact sequence is exercised by `test_unfunded_recapitalize_leaves_the_cash_book_overstating_custody` in `contracts/pool/tests/flows.rs:3408-3483`, which confirms custody reaches zero, the book still overstates it, and the exit fails inside the SAC transfer rather than in any pool guard.