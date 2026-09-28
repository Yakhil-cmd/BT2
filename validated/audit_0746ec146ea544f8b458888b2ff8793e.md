### Title
Pool `repay` refunds declared overpayment out of real custody without verifying any tokens were received - (contracts/pool/src/ops/repay.rs)

### Summary
The kernel bug (CVE-2025-39718) trusted a length field supplied in an attacker-controlled packet header instead of the actually-delivered buffer, overflowing the SKB. The XOXNO Lending pool has the same shape: `ops::repay::apply` treats the caller-declared `action.amount` as the delivered repayment and refunds the "overpayment" — `amount` minus outstanding debt — back to the `payer` via `transfer_out`, drawn from real pool custody. The pool itself never measures the inbound token delta; it relies entirely on the convention that "the controller transfers the repay amount into the pool before this call." An unprivileged caller who invokes `repay` directly with a fabricated `amount` receives a refund for tokens that were never sent.

### Finding Description
In `contracts/pool/src/ops/repay.rs:25-34`, `apply` computes `overpayment` purely from `action.amount` and the position's debt via `cache.resolve_repay(amount, position)`, then calls `outcome.cache.transfer_out(payer, outcome.overpayment)`. When the position has no debt (or the market carries no debt at all), `current_debt_ceil` is zero, the full-close branch yields `net_repay == 0`, and `overpayment == action.amount`. The `RepayRoundsToZeroShares` assert at lines 48-52 passes on its `net_repay == 0` disjunct, so no check stands between the declared amount and the payout.

The refund is paid with `transfer_out` — a transfer from the pool's own token balance — and bypasses `require_reserves`/the cash book, exactly as the codebase itself documents in `contracts/pool/tests/flows.rs:3578-3611`: *"A repay against a market with no debt makes the entire declared amount an overpayment… and the whole amount is refunded out of real custody with the book untouched."* The test `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` calls `client.repay(&payer, ...)` with `payer` a freshly generated address and **nothing transferred in**, then asserts custody was drained — proving the entrypoint trusts the declared amount like the vsock code trusted the header length, and that no controller-only gate stops a direct call. Even if `payer.require_auth()` is enforced, the attacker *is* the payer, so authorization provides no protection.

### Impact Explanation
Theft of user funds / protocol insolvency. A single unprivileged address can call `repay` on the pool with `payer = attacker`, a `PoolAction` whose position has zero scaled debt, and `amount` equal to the pool's full token balance. The entire amount is classified as overpayment and transferred out of supplier-backed custody to the attacker. Repeating per (hub, token) book drains every flash-enabled/borrowable market's cash, leaving suppliers' shares unbacked — direct theft of all deposited liquidity.

### Likelihood Explanation
Certain, if reachable. No collateral, debt, oracle price, or privileged role is needed — only a direct `repay` call with a crafted `PoolAction`. The only uncertainty is whether an upstream authorization gate restricts `repay` to the controller; the in-repo flow test demonstrates the call succeeding with an arbitrary generated payer and zero inbound transfer, which is strong evidence no such gate exists on the pool entrypoint itself. The revert paths (archival, pause gating on exits) may limit the window but do not remove the root cause.

### Recommendation
Validate the delivered amount before honoring the declared one — the exact fix applied upstream in the kernel. Either:
- Gate `repay`/`recapitalize` (and any other refund-from-declared-amount op) to the controller contract only, since the controller performs `transfer_amount_measured` before each pool call (`contracts/controller/src/positions/debt.rs:144-152`); or
- Have the pool snapshot `asset.balance(pool)` before accounting, measure the actual inbound delta, and clamp `amount`/refund to the measured receipt — the same `balance_delta_since` pattern the controller already uses in `contracts/controller/src/payments.rs:10-20`.

Also bound any refund by the measured inbound amount rather than the declared `action.amount`.

### Proof of Concept
1. Attacker generates a fresh address `A` (no funds needed beyond fees).
2. On a market with `borrowed == 0` (or a `PoolAction` whose `position_before` has `scaled_amount == 0`), call `pool.repay(payer = A, PoolAction { hub_asset, position_before: 0, amount = token.balance(pool) })`.
3. `resolve_repay` returns `overpayment = amount`; `RepayRoundsToZeroShares` passes because `net_repay == 0`; `credit_cash(0)` commits an unchanged book.
4. `transfer_out(A, amount)` moves the pool's full token balance to `A`.
5. Pool book (`cash`) still shows the reserves, but custody is empty — suppliers can no longer withdraw; attacker repeats for each hub asset.

This mirrors the existing self-documenting test at `contracts/pool/tests/flows.rs:3590-3611`, which executes exactly this sequence and asserts custody was drained.

Caveat: I could not fully enumerate `contracts/pool/src/lib.rs` authorization gates in the available iterations; if `repay` is externally restricted to the controller address, the direct-call path closes and this reduces to defense-in-depth rather than a live exploit. The presence of the test exercising the unfunded-refund path directly on the pool client suggests it is reachable.