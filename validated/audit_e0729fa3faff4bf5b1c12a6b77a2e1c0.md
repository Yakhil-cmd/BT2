### Title
Pool `repay` and `recapitalize` refund declared-but-never-received amounts out of real custody - (`contracts/pool/src/ops/repay.rs`, `contracts/pool/src/ops/recapitalize.rs`)

### Summary
The WEBrick smuggling bug is a desync between two interpreters of the same request: the front-end honors `Transfer-Encoding`, the back-end honors `Content-Length`, and each "sees" a different body boundary. The XOXNO Lending pool has the same shape: `repay` and `recapitalize` are told a **declared** inbound `amount` (the "Content-Length") but the pool **never measures or pulls the actual token receipt** (the real "body"). It trusts that "the controller transfers the repay amount into the pool before this call" (`repay.rs:3`), then computes an `overpayment`/`refund` from the declared number and executes `transfer_out` of real custodied tokens — without debiting `cash` and without `require_reserves`. Any gap between declared amount and actual inbound funding is paid out of other users' deposits, while the cash book is left untouched.

### Finding Description
In `contracts/pool/src/ops/repay.rs`:

```rust
let (burned, overpayment) = cache.resolve_repay(amount, position);
let net_repay = amount.checked_sub(overpayment)...
assert_with_error!(env, net_repay == 0 || burned.raw() > 0, RepayRoundsToZeroShares);
cache.credit_cash(net_repay);
...
outcome.cache.transfer_out(payer, outcome.overpayment);
```

`overpayment = amount − current_debt_ceil`. On a market with no debt, `resolve_repay` takes the full-close branch, `net_repay = 0`, the `RepayRoundsToZeroShares` assert passes on its `net_repay == 0` disjunct, and the **entire declared `amount` is refunded** — straight out of pool custody.

`contracts/pool/src/ops/recapitalize.rs` has the identical structure: `applied = amount.min(backing_shortfall)`, `refund = amount − applied`, then `transfer_out(&payer, refund)`. A market with zero backing shortfall refunds 100% of the declared amount.

Neither refund is drawn from an inbound measurement. There is no `balance_delta_since`, no `transfer` pull, no check that `amount` tokens actually arrived — the pool only assumes a trusted pre-funder. The pool's own test suite demonstrates the exploit end-to-end (`contracts/pool/tests/flows.rs:3578-3611`): `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` calls `repay(payer, action{custody_before})` with a comment stating "**Nothing transferred in**, no debt to retire: the whole amount is 'excess'", then asserts custody is drained to `payer` while the book is untouched.

### Impact Explanation
Theft of user funds / protocol insolvency. The attacker calls `pool.repay(self, HubAssetKey{hub, asset}, amount = pool_token_balance)` (or `recapitalize`) on a market whose outstanding debt (or backing shortfall) is less than `amount`. The pool transfers `overpayment`/`refund` tokens from real custody to the attacker, yet `cash` is never debited — so the reserve book still reports the stolen funds as present. Repeated or large calls drain the shared physical pool balance backing every (hub, token) book, leaving suppliers' claims unbacked (INV-ACCT-02 violated: book ≠ custody).

### Likelihood Explanation
Requires only that the `repay`/`recapitalize` entrypoints accept a caller-supplied `payer`/`action.amount` with `payer.require_auth()` — which the attacker's own call satisfies — rather than being restricted to the controller. The unit test invokes `repay` with only `payer` and an action, consistent with payer-level auth. No privileged role, oracle manipulation, or token exotica is needed; it works on plain SAC tokens on any market where declared amount exceeds debt/shortfall (e.g., a fresh or fully-repaid market where `current_debt_ceil == 0`). If the pool entrypoint is in fact gated to the controller address only, this reduces to a trusted-caller invariant and the analog does not hold — that gating is the one point I could not fully confirm from `pool/src/lib.rs` within the available context.

### Recommendation
Make the pool settle on **measured** receipts, matching INV-ACCT-03 everywhere else: snapshot `token::Client::balance(pool)` at entry, compute `received = balance_after − balance_before` after an explicit pull (or require the caller to pass a proof-of-funding), and bound `net_repay + overpayment ≤ received`. At minimum, cap `overpayment`/`refund` at the measured inbound delta and subject the refund transfer to the same reserve checks (`require_reserves`) as other outflows, so a declared-but-unfunded "Content-Length" can never exceed the actual delivered "body".

### Proof of Concept
```text
// Market with asset A: suppliers' deposits in pool custody, outstanding debt = 0.
// Attacker (any address) calls directly on the pool:
pool.repay(
    payer  = attacker,                    // attacker's own auth — freely given
    action = PoolAction { hub_asset: (hub, A), amount: pool_balance_A }
);
// resolve_repay: current_debt_ceil = 0 → overpayment = amount, net_repay = 0
// RepayRoundsToZeroShares assert passes (net_repay == 0 branch)
// cache.transfer_out(attacker, pool_balance_A) — drains custody, cash book unchanged
```
Mirrored by the existing test `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` in `contracts/pool/tests/flows.rs:3590-3611`, which performs exactly this call and asserts custody is drained with the book untouched. The `recapitalize` variant is identical with `amount` refunded in full on any fully-backed market.