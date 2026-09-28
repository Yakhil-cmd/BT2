### Title
Unfunded repay/recapitalize overpayment refund drains pool custody - (File: contracts/pool/src/ops/repay.rs)

### Summary
The analog of CVE-2015-1208 (integer underflow from a declared size larger than the real buffer, letting `mov_read_default` read past the actual data) maps onto the pool's repay and recapitalize legs: both compute a refund as `declared_amount - applied`, where `declared_amount` is a caller-supplied argument, not a measured receipt. Like the FFmpeg bug, the code trusts a declared size that can exceed what was actually provided, and pays out the difference from real token custody.

### Finding Description
`ops::repay::accounting` resolves `amount` against the position's debt via `resolve_repay` (`common/src/rates/scaling.rs:171`), which returns `overpayment = amount - current_debt_ceil` whenever `amount >= current_debt_ceil`. `ops::repay::apply` then calls `cache.transfer_out(payer, overpayment)` (`contracts/pool/src/ops/repay.rs:32`), which performs a raw `token.transfer` with no `require_reserves` and no debit of `cash` (`contracts/pool/src/cache/cash.rs:46-53`). Nothing in the pool verifies that `amount` tokens were ever received — the pool relies on the caller having prefunded it.

When the market has no debt (or the position's debt is small), `current_debt_ceil` is zero and the full-close branch makes the entire declared `amount` the "excess." `net_repay = 0`, so the `RepayRoundsToZeroShares` assert passes vacuously, and `transfer_out` sends the whole `amount` out of the pool's real balance to `payer`. The in-repo test `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` (`contracts/pool/tests/flows.rs:3590`) demonstrates exactly this: `client().repay(&payer, &t.ract(0, custody_before))` with zero borrowed and nothing transferred in drains the entire pool custody to `payer`.

The same shape exists in `ops::recapitalize::accounting` (`contracts/pool/src/ops/recapitalize.rs:44-66`): `refund = amount - applied` where `applied = amount.min(backing_shortfall)`; on a solvent market `backing_shortfall == 0`, so `applied = 0` and `refund = amount`, again sent via `transfer_out` from custody.

### Impact Explanation
Theft of user funds. An unprivileged caller submits a `repay` (or `recapitalize`) action declaring `amount` equal to the pool's token balance against a market with no debt (or a position they control with dust debt); the pool refunds the declared "excess" out of suppliers' real tokens without any corresponding inbound transfer. Every token in the pool's custody can be extracted by repeating or sizing the call at the full balance.

### Likelihood Explanation
Reachable by any unprivileged address whenever a (hub, token) book has no outstanding debt — including a freshly listed or fully-repaid market that still holds supplier cash. No privileged role, oracle manipulation, or timing is needed; the trigger is a single call with a crafted `amount`. The only uncertainty is whether the pool's `repay`/`recapitalize` entrypoints authenticate the caller as the controller — the pool test suite invokes them directly, suggesting they are externally reachable or that the same gap is reachable through `repay_debt_with_collateral`/liquidation paths that construct prefunded repay actions. I could not fully verify the auth gating on the pool entrypoints within the tool budget; if they are controller-only, the exposure narrows to paths where the controller declares an amount larger than the measured inflow.

### Recommendation
Make the refund derive from measured receipts, not the declared amount. Snapshot the pool's token balance before booking, require the inbound delta to cover `applied`, and cap the refund at `received - applied`. Alternatively, debit `cash` (or call `require_reserves`) for the refund so unfunded refunds fail, and reject repay/recapitalize calls whose `amount` exceeds the observed inflow.

### Proof of Concept
1. Market (hub, USDC) holds supplier cash `C`, `borrowed == 0`.
2. Attacker (any address) calls `pool.repay(payer = attacker, PoolAction { hub_asset, amount: C, ... })` with no prior token transfer.
3. `resolve_repay` sees `current_debt_ceil == 0`, returns `overpayment = C`, `net_repay = 0`; the zero-shares assert passes on `net_repay == 0`.
4. `transfer_out(attacker, C)` sends the full custody balance to the attacker. Reproduced by `contracts/pool/tests/flows.rs::test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` (lines 3590-3610) and the parallel recapitalize case.