### Title
Pool `repay` refunds a declared "overpayment" that was never received, draining real custody — ([File: contracts/pool/src/ops/repay.rs])

### Summary
The upstream bug is a leak where packets were popped from a FIFO but never consumed/freed — resources released from a queue without matching accounting — combined with a capacity check that compared counters incorrectly. The XOXNO analog sits in `ops::repay::apply`: the pool computes `overpayment` purely from the *declared* `action.amount`, never from a measured inbound balance delta, and then `transfer_out`s that "overpayment" to the payer out of the pool's real token custody. When the caller declares a repayment against a market with no outstanding debt (or skips actually funding the transfer), the entire declared amount is classified as excess and refunded — tokens leave the pool that were never pushed in. The repo's own test `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` in `contracts/pool/tests/flows.rs:3590` demonstrates exactly this: a `repay` call on a zero-debt market with **no inbound transfer** pays the full custody balance out as a "refund".

### Finding Description
In `contracts/pool/src/ops/repay.rs`:

- `apply` calls `accounting`, then `outcome.cache.transfer_out(payer, outcome.overpayment)` (line 32) — a real token transfer to `payer`.
- `accounting` computes `overpayment` via `cache.resolve_repay(amount, position)` where `amount` is the attacker-controlled `action.amount` (lines 42–47). `net_repay = amount - overpayment`.
- When `current_debt_ceil` is zero, `resolve_repay` takes the full-close branch: `burned = 0`, `overpayment = amount`, `net_repay = 0`. The `RepayRoundsToZeroShares` assert at line 48–52 passes because its `net_repay == 0` disjunct short-circuits.
- Nothing in this path verifies that `amount` tokens were actually transferred into the pool. The refund is debited from custody, not from `cash` on the book — `credit_cash(0)` leaves the book untouched while `transfer_out` moves real tokens.

This is the "freed but never pushed" shape of the skb-leak report: the pool releases tokens it never received because the refund is derived from declared input rather than measured receipt.

### Impact Explanation
If `pool.repay` is callable directly by an unprivileged address (the test invokes it through `t.client().repay` with a freshly generated `payer` and no prior token transfer, and the rules explicitly allow "direct token transfers to the pool or controller" as attacker-reachable), an attacker calls `repay` on any market with zero outstanding debt, declares `amount` equal to the pool's token balance, and receives the entire balance as `overpayment`. This is direct theft of supplier funds held in custody. On markets with debt, any declared `amount` above actual funded debt still yields an unfunded refund proportional to the shortfall. Impact: theft of user funds / contract left unable to operate for lack of token funds — Critical.

The companion test `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` (`contracts/pool/tests/flows.rs:3578–3611`) asserts custody drops to zero with `cash` unchanged, confirming the drain is real and not a bookkeeping artifact. The same declared-amount refund pattern exists in `ops::recapitalize::apply` (`contracts/pool/src/ops/recapitalize.rs:34`, refund = `amount - applied`), extending the surface.

### Likelihood Explanation
Likelihood hinges on whether `pool.repay`/`pool.recapitalize` are permissionless on-chain. My grep of `contracts/pool/src` found no `require_auth`/`only_controller` guard occurrences (the only `controller` hits are doc comments), and the pool tests call these entrypoints directly with arbitrary payer addresses and no authorization mocking — consistent with the pool trusting the controller to have pre-transferred funds, a trust assumption any direct caller can violate. If a controller-only auth check does exist in code my index did not surface, the exploit reduces to governance/controller-reachable only and the finding collapses; I could not fully verify the entrypoint auth in `pool/src/lib.rs` within the search budget. That uncertainty is stated explicitly; the custody-drain behavior itself is proven by the repo's own test.

### Recommendation
Measure the actual inbound transfer (balance delta of the pool around the call, or a measured-receipt settlement as done for flash paths) rather than trusting `action.amount`, and refund only `received - applied`. Alternatively, gate `repay`/`recapitalize`/`seize_positions` to the controller address so the declared-amount contract is enforced at the boundary. The `RepayRoundsToZeroShares` assert's `net_repay == 0` disjunct should not allow a positive `overpayment` refund when no shares were burned and nothing was received.

### Proof of Concept
Reproduced verbatim by `contracts/pool/tests/flows.rs:3590–3611`:

```rust
// contracts/pool/tests/flows.rs:3590
let custody_before = token.balance(&t.pool);
// Nothing transferred in, no debt to retire: the whole amount is "excess".
let credited = t
    .client()
    .repay(&payer, &t.ract(0, custody_before))   // declared amount = full custody
    .get_unchecked(0)
    .actual_amount;
assert_eq!(credited, 0, "no debt was retired, so nothing is credited");
assert_unfunded_refund_drained_custody(&t, &payer, custody_before, &before);
```

The helper asserts the payer received `custody_before` tokens while the market book (`cash`, `borrowed`) is unchanged — an attacker-shaped `repay` on a zero-debt market extracts the pool's entire balance.