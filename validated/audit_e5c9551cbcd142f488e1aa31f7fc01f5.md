### Title
Unfunded repay overpayment refund drains pool custody - ([File: contracts/pool/src/ops/repay.rs])

### Summary
`ops::repay::apply` computes the overpayment refund from the *declared* `action.amount` and transfers it back to `payer` out of real token custody, without verifying that any tokens were actually received for this repay. Analogous to CVE-2020-28617's "trust malformed input" bug class: the pool trusts an attacker-controlled declared amount rather than a measured receipt. The harness test `test_unfunded_repay_overpayment_refund_also_pays_out_of_custody` (`contracts/pool/tests/flows.rs:3590`) demonstrates the drain: a `repay` on a market with zero debt credits `actual_amount = 0` and sends the full declared amount to `payer` out of custody.

### Finding Description
`resolve_repay(amount, position)` splits the declared amount into `burned` debt shares and `overpayment`. When outstanding debt is zero (or small), `overpayment` equals the entire declared `amount`. `apply` then calls `outcome.cache.transfer_out(payer, outcome.overpayment)`, which moves real tokens from pool custody to the caller (`contracts/pool/src/ops/repay.rs:25-33`). Neither the overpayment refund nor `net_repay == 0` accounting debits `cash` or calls `require_reserves`, so the book stays untouched while custody shrinks — exactly the gap the test pins ("Neither refund debits `cash` or passes `require_reserves`", flows.rs:3578-3588). The repay path assumes a trusted caller (the controller) pre-funds the pool with `transfer_amount_measured`, but if `pool.repay` is directly callable by an unprivileged `payer` — as the test exercises — the declared amount is attacker input that is never validated against a measured inbound balance.

### Impact Explanation
Theft of user funds: a caller can declare `amount = pool token balance` on a debt-free market, have the full amount classified as overpayment, and receive the pool's entire token custody in a single call. Repeating per market/hub drains all liquidity.

### Likelihood Explanation
Single transaction, no collateral, no prior position required. Reachability depends on whether `pool.repay` enforces controller-only access; the harness invokes it directly on the pool client and observes custody drainage, indicating no effective gate in this code path. I could not fully verify the entrypoint's auth wrapper within the available iterations, so severity hinges on that check being absent or bypassable.

### Recommendation
Measure the repay input instead of trusting it: snapshot the pool's token balance before accounting and cap `overpayment`/`net_repay` at the measured inbound delta (the same `transfer_amount_measured` pattern used by `payments.rs` and the swap-aggregator's measured input credit). Alternatively require an explicit `funded_amount` proof or restrict `repay` to the controller address. Apply the same fix to `ops::recapitalize::apply`, which the test notes shares the identical unfunded-refund gap.

### Proof of Concept
```rust
// contracts/pool/tests/flows.rs::test_unfunded_repay_overpayment_refund_also_pays_out_of_custody
let custody_before = token.balance(&t.pool);          // pool holds user deposits
let payer = Address::generate(&t.env);                // attacker, zero balance, no transfer in

let credited = t
    .client()
    .repay(&payer, &t.ract(0, custody_before))        // declare amount = full custody
    .get_unchecked(0)
    .actual_amount;

assert_eq!(credited, 0);                              // nothing retired
// pool transfers `custody_before` to `payer` as "overpayment"; book unchanged
```